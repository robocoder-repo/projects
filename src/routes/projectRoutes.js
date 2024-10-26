
const express = require('express');
const projectController = require('../controllers/projectController');
const checkRole = require('../middleware/roleMiddleware');

const adminOnly = checkRole(['admin']);

const router = express.Router();

router.post('/projects', adminOnly, projectController.createProject);
router.get('/projects', projectController.getProjects);

module.exports = router;
