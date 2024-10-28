
const User = require('../models/user');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const logger = require('../config/logger');  // Assuming you have a logger configuration

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
        logger.error(`Error creating user: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
};

// Send 2FA code
exports.send2FACode = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const secret = speakeasy.generateSecret({ length: 20 });
        user.twoFactorSecret = secret.base32;
        await user.save();

        const token = speakeasy.totp({
            secret: user.twoFactorSecret,
            encoding: 'base32'
        });

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
            subject: 'Your 2FA Code',
            text: `Your 2FA code is: ${token}`,
        };

        await transporter.sendMail(mailOptions);
        logger.info(`2FA code sent to: ${user.email}`);
        res.status(200).json({ message: '2FA code sent' });
    } catch (error) {
        logger.error(`Error sending 2FA code: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
};

// Verify 2FA code
exports.verify2FACode = async (req, res) => {
    try {
        const { email, token } = req.body;
        const user = await User.findOne({ where: { email } });

        if (!user) {
            logger.warn(`2FA verification attempted for non-existent user: ${email}`);
            return res.status(404).json({ error: 'User not found' });
        }

        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token,
            window: 1
        });

        if (!verified) {
            logger.warn(`Invalid 2FA code attempted for user: ${email}`);
            return res.status(400).json({ error: 'Invalid 2FA code' });
        }

        const jwtToken = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info(`2FA code verified for: ${user.email}`);
        res.status(200).json({ token: jwtToken });
    } catch (error) {
        logger.error(`Error verifying 2FA code: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
};

// Role-based access control
exports.checkPermissions = (requiredPermissions) => {
    return (req, res, next) => {
        const { role, email } = req.user;
        const userPermissions = rolesPermissions[role] || [];

        const hasPermission = requiredPermissions.every(permission => userPermissions.includes(permission));
        if (!hasPermission) {
            logger.warn(`Access denied for user ${email} with role ${role}. Required permissions: ${requiredPermissions.join(', ')}`);
            return res.status(403).json({ error: 'You do not have permission to access this resource' });
        }

        logger.info(`Access granted for user ${email} with role ${role}. Required permissions: ${requiredPermissions.join(', ')}`);
        next();
    };
};

// User login and token generation
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });

        if (!user) {
            logger.warn(`Login attempted for non-existent user: ${email}`);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            logger.warn(`Invalid password attempt for user: ${email}`);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info(`User logged in successfully: ${email}`);
        res.status(200).json({ token });
    } catch (error) {
        logger.error(`Error during login: ${error.message}`);
        res.status(500).json({ error: 'An error occurred during login' });
    }
};

exports.getUsers = async (req, res) => {
    try {
        const users = await User.findAll();
        logger.info('Retrieved all users');
        res.status(200).json(users);
    } catch (error) {
        logger.error(`Error retrieving users: ${error.message}`);
        res.status(400).json({ error: 'An error occurred while retrieving users' });
    }
};

// Initiate password reset
exports.initiatePasswordReset = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) {
            logger.warn(`Password reset attempted for non-existent user: ${email}`);
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
        logger.info(`Password reset initiated for: ${user.email}`);
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

        logger.info(`Password reset completed for: ${user.email}`);
        res.status(200).json({ message: 'Password has been reset' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Send verification email
exports.sendVerificationEmail = async (req, res) => {
    try {
        const { email } = req.body;
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn(`Invalid email format: ${email}`);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const user = await User.findOne({ where: { email } });
        if (!user) {
            logger.warn(`Verification email requested for non-existent user: ${email}`);
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
        logger.info(`Verification email sent to: ${user.email}`);
        res.status(200).json({ message: 'Verification email sent' });
    } catch (error) {
        logger.error(`Error sending verification email: ${error.message}`);
        res.status(500).json({ error: 'An error occurred while sending the verification email' });
    }
};

// Verify user
exports.verifyUser = async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            logger.warn('Verification attempted without a token');
            return res.status(400).json({ error: 'Verification token is required' });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtError) {
            logger.warn(`Invalid verification token: ${jwtError.message}`);
            return res.status(400).json({ error: 'Invalid verification token' });
        }

        const user = await User.findOne({ where: { id: decoded.id, verificationToken: token } });

        if (!user) {
            logger.warn(`Verification attempted with valid token but non-existent user. User ID: ${decoded.id}`);
            return res.status(400).json({ error: 'Invalid or expired verification token' });
        }

        user.isVerified = true;
        user.verificationToken = null;
        await user.save();

        logger.info(`User verified successfully. User ID: ${user.id}`);
        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        logger.error(`Error during user verification: ${error.message}`);
        res.status(500).json({ error: 'An error occurred during verification' });
    }
};

// Issue refresh token
exports.issueRefreshToken = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            logger.warn(`Invalid email format for refresh token request: ${email}`);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const user = await User.findOne({ where: { email } });

        if (!user) {
            logger.warn(`Refresh token requested for non-existent user: ${email}`);
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        if (!user.isVerified) {
            logger.warn(`Refresh token requested for unverified user: ${email}`);
            return res.status(400).json({ error: 'User not verified' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            logger.warn(`Invalid password for refresh token request: ${email}`);
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const refreshToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        user.refreshToken = refreshToken;
        await user.save();

        logger.info(`Refresh token issued for user: ${email}`);
        res.status(200).json({ refreshToken });
    } catch (error) {
        logger.error(`Error issuing refresh token: ${error.message}`);
        res.status(500).json({ error: 'An error occurred while issuing the refresh token' });
    }
};

// Refresh token
exports.refreshToken = async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            logger.warn('Refresh token attempt without a token');
            return res.status(400).json({ error: 'Refresh token is required' });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtError) {
            logger.warn(`Invalid refresh token: ${jwtError.message}`);
            return res.status(400).json({ error: 'Invalid refresh token' });
        }

        const user = await User.findOne({ where: { id: decoded.id, refreshToken: token } });

        if (!user) {
            logger.warn(`Refresh token attempt with valid token but non-existent user. User ID: ${decoded.id}`);
            return res.status(400).json({ error: 'Invalid or expired refresh token' });
        }

        const newToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info(`New token issued for user ID: ${user.id}`);
        res.status(200).json({ token: newToken });
    } catch (error) {
        logger.error(`Error refreshing token: ${error.message}`);
        res.status(500).json({ error: 'An error occurred while refreshing the token' });
    }
};

// Complete password reset
exports.completePasswordReset = async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await User.findOne({
            where: {
                resetToken: token,
                resetTokenExpiry: { [Op.gt]: Date.now() }
            }
        });

        if (!user) {
            logger.warn(`Password reset attempted with invalid or expired token`);
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        if (newPassword.length < 8) {
            logger.warn(`Password reset attempted with weak password for user: ${user.email}`);
            return res.status(400).json({ error: 'Password must be at least 8 characters long' });
        }

        user.password = newPassword;
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();

        logger.info(`Password reset successful for user: ${user.email}`);
        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        logger.error(`Error during password reset: ${error.message}`);
        res.status(500).json({ error: 'An error occurred during password reset' });
    }
};
