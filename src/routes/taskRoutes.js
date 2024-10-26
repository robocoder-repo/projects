
const express = require('express');
const taskController = require('../controllers/taskController');
const checkRole = require('../middleware/roleMiddleware');
const { checkPermissions } = require('../controllers/userController');

const adminOnly = checkRole(['admin']);

const router = express.Router();

router.post('/tasks', adminOnly, checkPermissions(['manageTasks']), taskController.createTask);
router.get('/tasks', checkPermissions(['viewTasks']), taskController.getTasks);
router.get('/tasks', taskController.getTasks);

module.exports = router;
