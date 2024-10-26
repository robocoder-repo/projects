
const express = require('express');
const projectController = require('../controllers/projectController');
const checkRole = require('../middleware/roleMiddleware');
const { checkPermissions } = require('../controllers/userController');

const adminOnly = checkRole(['admin']);

const router = express.Router();

router.post('/projects', adminOnly, checkPermissions(['createProject']), projectController.createProject);
router.get('/projects', checkPermissions(['viewProjectDetails']), projectController.getProjects);
router.get('/projects', projectController.getProjects);

module.exports = router;
