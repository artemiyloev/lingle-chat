const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));
app.use(express.json());

const SECRET_KEY = 'lingle_secret_2026';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Создаём таблицы
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS rooms (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS room_messages (
    id SERIAL PRIMARY KEY,
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username TEXT NOT NULL,
    text TEXT NOT NULL,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

// --- АУТЕНТИФИКАЦИЯ ---
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1 OR username = $2', [email, username]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Почта или имя уже заняты' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера при регистрации' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Введите почту и пароль' });

  try {
    const result = await pool.query('SELECT id, username, password_hash FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Неверная почта или пароль' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Неверная почта или пароль' });

    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email } });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

// --- API ДЛЯ ЧАТОВ ---
app.get('/api/rooms', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM rooms ORDER BY id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка получения чатов' });
  }
});

app.post('/api/rooms', async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Введите название чата' });
  try {
    const result = await pool.query('INSERT INTO rooms (name) VALUES ($1) RETURNING id, name', [name]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Такое название уже есть или ошибка' });
  }
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

io.on('connection', async (socket) => {
  const currentUsername = socket.username || 'Гость';
  const currentUserId = socket.userId || null;
  let currentRoomId = null;

  // Подключение к комнате
  socket.on('join_room', async (roomId) => {
    // Выходим из старой комнаты
    if (currentRoomId) socket.leave(`room_${currentRoomId}`);
    currentRoomId = roomId;
    socket.join(`room_${roomId}`);
    
    // Загружаем историю
    const res = await pool.query(
      'SELECT * FROM room_messages WHERE room_id = $1 ORDER BY time ASC LIMIT 50',
      [roomId]
    );
    socket.emit('load_history', res.rows);
  });

  // Отправка сообщения
  socket.on('send_message', async (data) => {
    const { roomId, text } = data;
    if (!roomId || !text) return;

    const insert = await pool.query(
      'INSERT INTO room_messages (room_id, user_id, username, text) VALUES ($1, $2, $3, $4) RETURNING *',
      [roomId, currentUserId, currentUsername, text]
    );
    const savedMsg = insert.rows[0];
    io.to(`room_${roomId}`).emit('receive_message', savedMsg);
  });

  // --- WEBRTC СИГНАЛИНГ (ЗВОНКИ) ---
  socket.on('call_user', (data) => {
    // data: { targetRoomId, offer }
    // Отправляем приглашение всем в комнате (кроме себя)
    socket.to(`room_${data.targetRoomId}`).emit('incoming_call', {
      from: socket.id,
      fromUsername: currentUsername,
      offer: data.offer
    });
  });

  socket.on('answer_call', (data) => {
    // data: { targetId, answer }
    io.to(data.targetId).emit('call_answered', {
      answer: data.answer,
      from: socket.id
    });
  });

  socket.on('ice_candidate', (data) => {
    // data: { targetId, candidate }
    io.to(data.targetId).emit('ice_candidate', data.candidate);
  });

  // Завершение звонка
  socket.on('hangup', (data) => {
    socket.to(`room_${data.roomId}`).emit('call_ended');
  });

  socket.on('disconnect', () => {
    // Уведомляем комнату, если была
    if (currentRoomId) {
      socket.to(`room_${currentRoomId}`).emit('user_left', currentUsername);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Сервер Lingle с чатами и звонками работает!'));
