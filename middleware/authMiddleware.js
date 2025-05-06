const jwt = require('jsonwebtoken');
require('dotenv').config();

const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;

    // Check for token in the Authorization header
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1]; // Extract token

    try {
        // Verify token and decode payload
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user information to the request
        next(); // Proceed to the next middleware or route handler
    } catch (err) {
        console.error('Invalid token:', err.message);
        res.status(401).json({ error: 'Invalid token.' });
    }
};


module.exports = authenticate;
