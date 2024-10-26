
const express = require('express');
const userController = require('../controllers/userController');
const checkRole = require('../middleware/roleMiddleware');
const { checkPermissions } = require('../controllers/userController');

const adminOnly = checkRole(['admin']);

const router = express.Router();

router.post('/users', adminOnly, checkPermissions(['manageUsers']), userController.createUser);
router.get('/users', checkPermissions(['viewReports']), userController.getUsers);
router.get('/users', userController.getUsers);

// Password reset routes
router.post('/users/reset-password', userController.initiatePasswordReset);
router.post('/users/reset-password/complete', userController.completePasswordReset);

// Email verification routes
router.post('/users/send-verification-email', userController.sendVerificationEmail);
router.post('/users/verify', userController.verifyUser);

// Token routes
router.post('/users/issue-refresh-token', userController.issueRefreshToken);
router.post('/users/refresh-token', userController.refreshToken);

// User login route
router.post('/users/login', userController.login);

// 2FA routes
router.post('/users/send-2fa-code', userController.send2FACode);
router.post('/users/verify-2fa-code', userController.verify2FACode);

module.exports = router;
