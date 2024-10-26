
const jwt = require('jsonwebtoken');
require('dotenv').config();

const checkRole = (roles) => {
    return (req, res, next) => {
        const token = req.headers['authorization'];
        if (!token) {
            return res.status(403).json({ error: 'No token provided' });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to authenticate token' });
            }

            if (!roles.includes(decoded.role)) {
                return res.status(403).json({ error: 'You do not have permission to access this resource' });
            }

            req.user = decoded;
            next();
        });
    };
};

module.exports = checkRole;
