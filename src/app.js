
const express = require('express');
const bodyParser = require('body-parser');
const sequelize = require('../config/database');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Test database connection
sequelize.authenticate()
    .then(() => console.log('Database connected...'))
    .catch(err => console.log('Error: ' + err));

const projectRoutes = require('./routes/projectRoutes');
const taskRoutes = require('./routes/taskRoutes');
const userRoutes = require('./routes/userRoutes');

// Routes
app.use('/api', projectRoutes);
app.use('/api', taskRoutes);
app.use('/api', userRoutes);

app.get('/', (req, res) => {
    res.send('Welcome to the Project Management API');
});

sequelize.sync()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch(err => console.log('Error: ' + err));
