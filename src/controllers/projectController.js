
const Project = require('../models/project');
const Task = require('../models/task');

exports.createProject = async (req, res) => {
    try {
        const project = await Project.create(req.body);
        res.status(201).json(project);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

exports.getProjects = async (req, res) => {
    try {
        const projects = await Project.findAll({ include: Task });
        res.status(200).json(projects);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};
