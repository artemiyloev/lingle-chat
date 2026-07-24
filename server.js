const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));

// Подключаемся к базе данных (Render сам подставит DATABASE_URL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Создаём таблицу для сообщений, если её нет
pool.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    username TEXT,
    text TEXT,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

io.on('connection', async (socket) => {
  // Загружаем последние 50 сообщений из базы при подключении
  const res = await pool.query('SELECT * FROM messages ORDER BY time ASC LIMIT 50');
  socket.emit('load_history', res.rows);

  socket.on('send_message', async (data) => {
    const msg = {
      username: data.username || 'Аноним',
      text: data.text,
    };

    // Сохраняем сообщение в базу данных
    const insert = await pool.query(
      'INSERT INTO messages (username, text) VALUES ($1, $2) RETURNING *',
      [msg.username, msg.text]
    );
    const savedMsg = insert.rows[0];

    // Отправляем всем, кто онлайн
    io.emit('receive_message', savedMsg);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Сервер Lingle с базой данных работает!'));
