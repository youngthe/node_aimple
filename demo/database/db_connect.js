const db = require('mysql2');

const conn = db.createConnection({
    host: 'localhost',
    port: 3306,
    user: 'root',
    password : 'test',
    database : 'aimple'
});

module.exports = conn;