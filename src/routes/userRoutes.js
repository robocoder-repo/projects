
const express = require('express');
const userController = require('../controllers/userController');
const checkRole = require('../middleware/roleMiddleware');

const adminOnly = checkRole(['admin']);

const router = express.Router();

router.post('/users', adminOnly, userController.createUser);
router.get('/users', userController.getUsers);

module.exports = router;
