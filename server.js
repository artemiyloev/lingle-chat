const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));

let messages = [];

io.on('connection', (socket) => {
  socket.emit('load_history', messages);

  socket.on('send_message', (data) => {
    const msg = {
      id: socket.id,
      username: data.username || 'Аноним',
      text: data.text,
      time: new Date().toLocaleTimeString()
    };
    messages.push(msg);
    io.emit('receive_message', msg);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Сервер Lingle работает!'));
