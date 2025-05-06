const mysql = require('mysql2/promise'); 
require('dotenv').config();
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DATABASE_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ecommerce',  
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});
(async () => {
    try {
        const connection = await db.getConnection();
        console.log(`MySQL Connected to ${process.env.DB_NAME}...`);
        connection.release(); // Release connection back to the pool
    } catch (err) {
        console.error('Error connecting to MySQL:', err.message);
    }
})();
module.exports = db;
