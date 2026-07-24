 const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));
app.use(express.json());

const SECRET_KEY = 'lingle_secret_2026';

// Подключаемся к SQLite (файл создастся сам в папке сервера)
const db = new sqlite3.Database('./db.sqlite');

// Создаём таблицы
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS room_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER,
    user_id INTEGER,
    username TEXT NOT NULL,
    text TEXT NOT NULL,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
});

// --- АУТЕНТИФИКАЦИЯ ---
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });

  db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
    if (row) return res.status(409).json({ error: 'Почта или имя уже заняты' });

    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, hash], function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка регистрации' });
      const token = jwt.sign({ userId: this.lastID, username: username }, SECRET_KEY, { expiresIn: '7d' });
      res.json({ token, user: { id: this.lastID, username, email } });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Введите почту и пароль' });

  db.get('SELECT id, username, password_hash FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Неверная почта или пароль' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Неверная почта или пароль' });

    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email } });
  });
});

app.get('/api/rooms', (req, res) => {
  db.all('SELECT id, name FROM rooms ORDER BY id ASC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Ошибка загрузки' });
    res.json(rows);
  });
});

app.post('/api/rooms', (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Введите название' });
  db.run('INSERT INTO rooms (name) VALUES (?)', [name], function(err) {
    if (err) return res.status(500).json({ error: 'Ошибка создания комнаты' });
    res.json({ id: this.lastID, name });
  });
});

// --- СОКЕТЫ (ЧАТ + ЗВОНКИ) ---
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
  const currentUsername = socket.username || 'Гость';
  const currentUserId = socket.userId || null;
  let currentRoomId = null;

  socket.on('join_room', (roomId) => {
    if (currentRoomId) socket.leave(`room_${currentRoomId}`);
    currentRoomId = roomId;
    socket.join(`room_${roomId}`);

    db.all('SELECT * FROM room_messages WHERE room_id = ? ORDER BY time ASC LIMIT 50', [roomId], (err, rows) => {
      if (!err) socket.emit('load_history', rows);
    });
  });

  socket.on('send_message', (data) => {
    const { roomId, text } = data;
    if (!roomId || !text) return;

    db.run('INSERT INTO room_messages (room_id, user_id, username, text) VALUES (?, ?, ?, ?)', [roomId, currentUserId, currentUsername, text], function(err) {
      if (err) return;
      const savedMsg = { id: this.lastID, room_id: roomId, user_id: currentUserId, username: currentUsername, text: text, time: new Date() };
      io.to(`room_${roomId}`).emit('receive_message', savedMsg);
    });
  });

  // WEBRTC ЗВОНКИ
  socket.on('call_user', (data) => {
    socket.to(`room_${data.targetRoomId}`).emit('incoming_call', {
      from: socket.id,
      fromUsername: currentUsername,
      offer: data.offer
    });
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
server.listen(PORT, () => console.log('✅ Lingle на SQLite с регистрацией и звонками!'));
