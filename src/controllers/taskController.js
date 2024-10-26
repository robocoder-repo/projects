
const Task = require('../models/task');

exports.createTask = async (req, res) => {
    try {
        // Validation logic
        if (!req.body.title) {
            return res.status(400).json({ error: 'Task title is required' });
        }
        const task = await Task.create(req.body);
        res.status(201).json(task);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

exports.getTasks = async (req, res) => {
    try {
        const tasks = await Task.findAll();
        res.status(200).json(tasks);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};
