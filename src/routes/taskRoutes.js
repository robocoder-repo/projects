
const express = require('express');
const taskController = require('../controllers/taskController');

const router = express.Router();

router.post('/tasks', taskController.createTask);
router.get('/tasks', taskController.getTasks);

module.exports = router;
