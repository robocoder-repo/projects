
const User = require('../models/user');

exports.createUser = async (req, res) => {
    try {
        // Validation logic
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }

        const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters long' });
        }
        const user = await User.create(req.body);
        logger.info(`User created: ${user.email}`);
        res.status(201).json(user);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// Role-based access control
exports.checkPermissions = (requiredPermissions) => {
    return (req, res, next) => {
        const { role } = req.user;
        const userPermissions = rolesPermissions[role] || [];

        const hasPermission = requiredPermissions.every(permission => userPermissions.includes(permission));
        if (!hasPermission) {
            return res.status(403).json({ error: 'You do not have permission to access this resource' });
        }

        next();
    };
};

// User login and token generation
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.getUsers = async (req, res) => {
    try {
        const users = await User.findAll();
        res.status(200).json(users);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

// Initiate password reset
exports.initiatePasswordReset = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL,
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.


            Please click on the following link, or paste this into your browser to complete the process:


            http://${req.headers.host}/reset/${resetToken}


            If you did not request this, please ignore this email and your password will remain unchanged.
`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Password reset email sent' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Complete password reset
exports.completePasswordReset = async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await User.findOne({
            where: {
                resetToken: token,
                resetTokenExpiry: { [Op.gt]: Date.now() },
            },
        });

        if (!user) {
            return res.status(400).json({ error: 'Password reset token is invalid or has expired' });
        }

        user.password = newPassword;
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();

        res.status(200).json({ message: 'Password has been reset' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Send verification email
exports.sendVerificationEmail = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const verificationToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.verificationToken = verificationToken;
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL,
            subject: 'Email Verification',
            text: `Please verify your email by clicking the following link: http://${req.headers.host}/verify/${verificationToken}`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Verification email sent' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Verify user
exports.verifyUser = async (req, res) => {
    try {
        const { token } = req.body;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ where: { id: decoded.id, verificationToken: token } });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired verification token' });
        }

        user.isVerified = true;
        user.verificationToken = null;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Issue refresh token
exports.issueRefreshToken = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });

        if (!user || !user.isVerified) {
            return res.status(400).json({ error: 'Invalid email or user not verified' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const refreshToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        user.refreshToken = refreshToken;
        await user.save();

        res.status(200).json({ refreshToken });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Refresh token
exports.refreshToken = async (req, res) => {
    try {
        const { token } = req.body;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ where: { id: decoded.id, refreshToken: token } });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired refresh token' });
        }

        const newToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token: newToken });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
