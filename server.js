const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));
app.use(express.json());

const SECRET_KEY = 'lingle_secret_2026';
const db = new Database('db.sqlite');

// Создаём таблицы (добавлена таблица user_chats для списка диалогов)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS room_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    user_id INTEGER,
    username TEXT NOT NULL,
    text TEXT NOT NULL,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS user_chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    chat_room_id TEXT NOT NULL,
    target_user_id INTEGER NOT NULL,
    target_username TEXT NOT NULL,
    last_message TEXT DEFAULT '',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, chat_room_id)
  );
`);

// --- АУТЕНТИФИКАЦИЯ ---
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });
  try {
    if (db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username))
      return res.status(409).json({ error: 'Почта или имя уже заняты' });
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, hash);
    const token = jwt.sign({ userId: info.lastInsertRowid, username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: info.lastInsertRowid, username, email } });
  } catch (err) { res.status(500).json({ error: 'Ошибка регистрации' }); }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Введите почту и пароль' });
  try {
    const user = db.prepare('SELECT id, username, password_hash FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Неверная почта или пароль' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Неверная почта или пароль' });
    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email } });
  } catch (err) { res.status(500).json({ error: 'Ошибка входа' }); }
});

// --- API для получения списка диалогов ---
app.get('/api/my-chats', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.userId;
    const chats = db.prepare('SELECT * FROM user_chats WHERE user_id = ? ORDER BY updated_at DESC').all(userId);
    res.json(chats);
  } catch (err) { res.status(500).json({ error: 'Ошибка загрузки диалогов' }); }
});

// --- ПОИСК ПОЛЬЗОВАТЕЛЕЙ ---
app.get('/api/search-users', (req, res) => {
  const query = req.query.q;
  if (!query) return res.json([]);
  try {
    const users = db.prepare('SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ? OR id LIKE ? LIMIT 20').all(`%${query}%`, `%${query}%`, `%${query}%`);
    res.json(users);
  } catch (err) { res.status(500).json({ error: 'Ошибка поиска' }); }
});

// --- СОКЕТЫ ---
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) { socket.isGuest = true; return next(); }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    next();
  } catch (err) { socket.isGuest = true; next(); }
});

io.on('connection', (socket) => {
  const currentUserId = socket.userId;
  const currentUsername = socket.username;
  let currentRoomId = null;

  socket.emit('your_id', currentUserId);

  socket.on('join_room', (roomId, targetUserId, targetUsername) => {
    if (currentRoomId) socket.leave(`room_${currentRoomId}`);
    currentRoomId = roomId;
    socket.join(`room_${roomId}`);

    // Сохраняем диалог в список чатов пользователя
    if (targetUserId && currentUserId) {
      try {
        db.prepare(`
          INSERT INTO user_chats (user_id, chat_room_id, target_user_id, target_username) 
          VALUES (?, ?, ?, ?)
          ON CONFLICT(user_id, chat_room_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
        `).run(currentUserId, roomId, targetUserId, targetUsername);
      } catch (e) { /* Игнорируем, если уже есть */ }
    }

    const rows = db.prepare('SELECT * FROM room_messages WHERE room_id = ? ORDER BY time ASC LIMIT 50').all(roomId);
    socket.emit('load_history', rows);
  });

  socket.on('send_message', (data) => {
    const { roomId, text } = data;
    if (!roomId || !text) return;
    const info = db.prepare('INSERT INTO room_messages (room_id, user_id, username, text) VALUES (?, ?, ?, ?)').run(roomId, currentUserId, currentUsername, text);
    const savedMsg = { id: info.lastInsertRowid, room_id: roomId, user_id: currentUserId, username: currentUsername, text, time: new Date() };
    io.to(`room_${roomId}`).emit('receive_message', savedMsg);
  });

  // Звонки (WebRTC) остаются без изменений
  socket.on('call_user', (data) => socket.to(`room_${data.targetRoomId}`).emit('incoming_call', { from: socket.id, fromUsername: currentUsername, offer: data.offer }));
  socket.on('answer_call', (data) => io.to(data.targetId).emit('call_answered', { answer: data.answer, from: socket.id }));
  socket.on('ice_candidate', (data) => io.to(data.targetId).emit('ice_candidate', data.candidate));
  socket.on('hangup', (data) => socket.to(`room_${data.roomId}`).emit('call_ended'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('✅ Lingle с чатами как в TG!')); 
