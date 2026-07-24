const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));
app.use(express.json());

const SECRET_KEY = 'lingle_secret_2026';

// Настройка загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
  res.json({ filename: req.file.filename, originalname: req.file.originalname, url: `/uploads/${req.file.filename}` });
});
app.use('/uploads', express.static('uploads'));

// Подключаем SQLite
const db = new Database('db.sqlite');

// Создаём таблицы
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS room_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER,
    user_id INTEGER,
    username TEXT NOT NULL,
    text TEXT NOT NULL,
    file TEXT,            -- ссылка на файл, если есть
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

// --- Регистрация / вход ---
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
    if (existing) return res.status(409).json({ error: 'Почта или имя уже заняты' });

    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, hash);
    const token = jwt.sign({ userId: info.lastInsertRowid, username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: info.lastInsertRowid, username, email } });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка регистрации' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Введите почту и пароль' });

  try {
    const user = db.prepare('SELECT id, username, password_hash FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Неверная почта или пароль' });
    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Неверная почта или пароль' });
    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email } });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

app.get('/api/rooms', (req, res) => {
  try {
    const rows = db.prepare('SELECT id, name FROM rooms ORDER BY id ASC').all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка загрузки' });
  }
});

app.post('/api/rooms', (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Введите название' });
  try {
    const info = db.prepare('INSERT INTO rooms (name) VALUES (?)').run(name);
    res.json({ id: info.lastInsertRowid, name });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка создания комнаты' });
  }
});

// --- Сокеты (чат + голосовые сообщения) ---
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
    const rows = db.prepare('SELECT * FROM room_messages WHERE room_id = ? ORDER BY time ASC LIMIT 50').all(roomId);
    socket.emit('load_history', rows);
  });

  socket.on('send_message', (data) => {
    const { roomId, text, file } = data;
    if (!roomId) return;

    const stmt = db.prepare('INSERT INTO room_messages (room_id, user_id, username, text, file) VALUES (?, ?, ?, ?, ?)');
    const info = stmt.run(roomId, currentUserId, currentUsername, text || '', file || null);
    const savedMsg = {
      id: info.lastInsertRowid,
      room_id: roomId,
      user_id: currentUserId,
      username: currentUsername,
      text: text || '',
      file: file || null,
      time: new Date()
    };
    io.to(`room_${roomId}`).emit('receive_message', savedMsg);
  });

  // (Звонки убираем — они всё равно не работают на Render)
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('✅ Lingle с голосовыми сообщениями!'));
