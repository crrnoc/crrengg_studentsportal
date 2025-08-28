const mysql = require('mysql2');
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'tarun123',
  database: 'noc'
});

module.exports = db;
