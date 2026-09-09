const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));
app.use(express.json());

const SECRET_KEY = 'lingle_secret_2026';
const db = new Database('db.sqlite');

// --- Настройки почты (замени на свои SMTP) ---
const transporter = nodemailer.createTransport({
  host: 'smtp.mail.ru', // smtp.yandex.ru / smtp.gmail.com
  port: 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER, // твой email
    pass: process.env.SMTP_PASS  // пароль приложения
  }
});

// --- Таблицы ---
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
  CREATE TABLE IF NOT EXISTS verification_codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

// --- Генерация кода ---
function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

async function sendVerificationEmail(email, code) {
  await transporter.sendMail({
    from: `"Lingle" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Код подтверждения Lingle',
    text: `Ваш код подтверждения: ${code}`
  });
}

// --- Отправка кода ---
app.post('/api/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email не указан' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Этот email уже зарегистрирован' });

  const code = generateCode();
  const expiresAt = Date.now() + 5 * 60 * 1000;

  db.prepare(`
    INSERT INTO verification_codes (email, code, expires_at) 
    VALUES (?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET code = excluded.code, expires_at = excluded.expires_at
  `).run(email, code, expiresAt);

  try {
    await sendVerificationEmail(email, code);
    res.json({ success: true, message: 'Код отправлен на почту' });
  } catch (err) {
    console.error('Ошибка отправки письма:', err.message);
    res.status(500).json({ error: 'Не удалось отправить письмо. Проверьте SMTP-настройки.' });
  }
});

// --- Подтверждение кода ---
app.post('/api/verify-code', (req, res) => {
  const { email, code, username, password } = req.body;
  if (!email || !code || !username || !password) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }

  const record = db.prepare('SELECT * FROM verification_codes WHERE email = ?').get(email);
  if (!record) return res.status(400).json({ error: 'Код не запрашивался' });
  if (record.code !== code) return res.status(400).json({ error: 'Неверный код' });
  if (Date.now() > record.expires_at) {
    db.prepare('DELETE FROM verification_codes WHERE email = ?').run(email);
    return res.status(400).json({ error: 'Код истёк, запросите новый' });
  }

  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, hash);
    db.prepare('DELETE FROM verification_codes WHERE email = ?').run(email);
    const token = jwt.sign({ userId: info.lastInsertRowid, username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: info.lastInsertRowid, username, email } });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка создания пользователя' });
  }
});

// --- Вход ---
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'Введите логин/почту и пароль' });

  try {
    const user = db.prepare('SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?').get(login, login);
    if (!user) return res.status(401).json({ error: 'Неверный логин/почта или пароль' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Неверный логин/почта или пароль' });

    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

// --- Список личных чатов ---
app.get('/api/my-chats', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.userId;
    const chats = db.prepare('SELECT * FROM user_chats WHERE user_id = ? ORDER BY updated_at DESC').all(userId);
    res.json(chats);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка загрузки диалогов' });
  }
});

// --- Поиск пользователей ---
app.get('/api/search-users', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.userId;
    const query = req.query.q;
    if (!query) return res.json([]);

    const users = db.prepare(`
      SELECT id, username, email FROM users 
      WHERE (username LIKE ? OR email LIKE ? OR id LIKE ?) AND id != ?
      LIMIT 20
    `).all(`%${query}%`, `%${query}%`, `%${query}%`, userId);

    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка поиска' });
  }
});

// --- Сокеты ---
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) { socket.isGuest = true; return next(); }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    next();
  } catch (err) {
    socket.isGuest = true;
    next();
  }
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

    if (targetUserId && currentUserId) {
      try {
        db.prepare(`
          INSERT INTO user_chats (user_id, chat_room_id, target_user_id, target_username) 
          VALUES (?, ?, ?, ?)
          ON CONFLICT(user_id, chat_room_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
        `).run(currentUserId, roomId, targetUserId, targetUsername);
      } catch (e) { /* Игнорируем */ }
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

  // Звонки
  socket.on('call_user', (data) => {
    socket.to(`room_${data.targetRoomId}`).emit('incoming_call', { from: socket.id, fromUsername: currentUsername, offer: data.offer });
  });

  socket.on('answer_call', (data) => {
    io.to(data.targetId).emit('call_answered', { answer: data.answer, from: socket.id });
  });

  socket.on('ice_candidate', (data) => {
    io.to(data.targetId).emit('ice_candidate', data.candidate);
  });

  socket.on('hangup', (data) => {
    socket.to(`room_${data.roomId}`).emit('call_ended');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('✅ Lingle полностью работает!')); 
