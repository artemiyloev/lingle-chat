const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ============================================================
//  ХРАНИЛИЩЕ (вместо db.js + store.js)
// ============================================================
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function load(name, fallback = []) {
  const p = path.join(DATA_DIR, `${name}.json`);
  if (!fs.existsSync(p)) return fallback;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; }
}
function save(name, data) {
  const p = path.join(DATA_DIR, `${name}.json`);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, p);
}

// ---------- USERS ----------
function getUsers() { return load('users', []); }

function findUserByLogin(login) {
  return getUsers().find(u => u.username === login);
}

function createUser(username, password) {
  const users = getUsers();
  if (users.some(u => u.username === username)) throw new Error('Это имя уже занято');
  const user = {
    id: users.length ? Math.max(...users.map(u => u.id)) + 1 : 1,
    username,
    password_hash: bcrypt.hashSync(password, 10),
    created_at: new Date().toISOString()
  };
  users.push(user);
  save('users', users);
  return user;
}

function searchUsers(query, excludeId) {
  const q = query.toLowerCase();
  return getUsers()
    .filter(u => u.id !== excludeId && u.username.toLowerCase().includes(q))
    .slice(0, 20)
    .map(({ password_hash, ...rest }) => rest);
}

// ---------- MESSAGES ----------
function getMessages(roomId, limit = 50) {
  return load('messages', []).filter(m => m.room_id === roomId).slice(-limit);
}

function addMessage(msg) {
  const all = load('messages', []);
  const id = all.length ? Math.max(...all.map(m => m.id)) + 1 : 1;
  const record = { id, ...msg, time: new Date().toISOString() };
  all.push(record);
  save('messages', all);
  return record;
}

// ---------- CHATS ----------
function getChatsForUser(userId) {
  return load('chats', [])
    .filter(c => c.user_id === userId)
    .sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
}

function upsertChat({ userId, chatRoomId, targetUserId, targetUsername }) {
  const all = load('chats', []);
  const idx = all.findIndex(c => c.user_id === userId && c.chat_room_id === chatRoomId);
  const now = new Date().toISOString();
  if (idx >= 0) {
    all[idx].updated_at = now;
  } else {
    all.push({
      id: all.length ? Math.max(...all.map(c => c.id)) + 1 : 1,
      user_id: userId,
      chat_room_id: chatRoomId,
      target_user_id: targetUserId,
      target_username: targetUsername,
      last_message: '',
      updated_at: now
    });
  }
  save('chats', all);
}

function updateLastMessage(roomId, text) {
  const all = load('chats', []);
  let changed = false;
  all.forEach(c => {
    if (c.chat_room_id === roomId) {
      c.last_message = text.slice(0, 100);
      c.updated_at = new Date().toISOString();
      changed = true;
    }
  });
  if (changed) save('chats', all);
}

// ============================================================
//  СЕРВЕР
// ============================================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

app.set('trust proxy', 1);
app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));

const SECRET_KEY = process.env.JWT_SECRET || 'lingle_dev_only_change_me';

// ---------- UPLOADS ----------
const uploadDir = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /image|audio|video|pdf|text|zip|octet-stream/.test(file.mimetype);
    cb(ok ? null : new Error('Недопустимый тип файла'), ok);
  }
});

app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
}, express.static(uploadDir));

// ---------- AUTH MIDDLEWARE ----------
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch {
    res.status(401).json({ error: 'Невалидный токен' });
  }
}

// ---------- AUTH ROUTES ----------
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Заполните логин и пароль' });
  if (username.length < 3) return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  try {
    const user = createUser(username, password);
    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (e) {
    res.status(409).json({ error: e.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Введите логин и пароль' });
  const user = findUserByLogin(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username } });
});

// ---------- CHATS / SEARCH ----------
app.get('/api/my-chats', auth, (req, res) => {
  res.json(getChatsForUser(req.user.userId));
});

app.get('/api/search-users', auth, (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  res.json(searchUsers(q, req.user.userId));
});

// ---------- UPLOAD ----------
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
  res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname });
});

// ============================================================
//  SOCKETS
// ============================================================
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});

const onlineUsers = new Map();

io.on('connection', (socket) => {
  const { userId, username } = socket;
  onlineUsers.set(userId, socket.id);
  socket.emit('your_id', userId);

  socket.on('join_room', ({ roomId, targetUserId, targetUsername }) => {
    socket.join(`room_${roomId}`);
    socket.currentRoomId = roomId;

    upsertChat({ userId, chatRoomId: roomId, targetUserId, targetUsername });
    upsertChat({ userId: targetUserId, chatRoomId: roomId, targetUserId: userId, targetUsername: username });

    socket.emit('load_history', getMessages(roomId));
  });

  socket.on('send_message', ({ roomId, text, fileUrl }) => {
    if (!roomId || !text) return;
    const saved = addMessage({
      room_id: roomId,
      user_id: userId,
      username,
      text,
      file_url: fileUrl || null
    });
    updateLastMessage(roomId, text);
    io.to(`room_${roomId}`).emit('receive_message', saved);
  });

  // ---------- ЗВОНКИ ----------
  socket.on('call_user', ({ targetUserId, offer, video }) => {
    const targetSocket = onlineUsers.get(targetUserId);
    if (!targetSocket) return socket.emit('call_failed', { reason: 'Пользователь не в сети' });
    io.to(targetSocket).emit('incoming_call', {
      from: socket.id,
      fromUserId: userId,
      fromUsername: username,
      offer,
      video
    });
  });

  socket.on('answer_call', ({ targetSocketId, answer }) => {
    io.to(targetSocketId).emit('call_answered', { answer, from: socket.id });
  });

  socket.on('ice_candidate', ({ targetSocketId, candidate }) => {
    io.to(targetSocketId).emit('ice_candidate', candidate);
  });

  socket.on('hangup', ({ targetSocketId }) => {
    if (targetSocketId) io.to(targetSocketId).emit('call_ended');
  });

  socket.on('disconnect', () => {
    if (onlineUsers.get(userId) === socket.id) onlineUsers.delete(userId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('✅ Lingle работает на порту ' + PORT));
