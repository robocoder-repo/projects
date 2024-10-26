
const express = require('express');
const taskController = require('../controllers/taskController');
const checkRole = require('../middleware/roleMiddleware');

const adminOnly = checkRole(['admin']);

const router = express.Router();

router.post('/tasks', adminOnly, taskController.createTask);
router.get('/tasks', taskController.getTasks);

module.exports = router;
