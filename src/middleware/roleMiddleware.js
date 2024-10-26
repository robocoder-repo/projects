
const jwt = require('jsonwebtoken');
require('dotenv').config();

const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});

const rolesPermissions = {
    admin: ['createProject', 'manageUsers', 'manageTasks', 'viewReports'],
    manager: ['manageProjects', 'manageTasks', 'viewReports', 'viewProjectDetails'],
    member: ['viewTasks', 'updateTasks', 'comment'],
};

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
