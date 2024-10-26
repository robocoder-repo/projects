
const express = require('express');
const bodyParser = require('body-parser');
const sequelize = require('../config/database');
const winston = require('winston');

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});
require('dotenv').config();

const fs = require('fs');
const https = require('https');

const app = express();

const privateKey = fs.readFileSync('path/to/private.key', 'utf8');
const certificate = fs.readFileSync('path/to/certificate.crt', 'utf8');
const ca = fs.readFileSync('path/to/ca_bundle.crt', 'utf8');

const credentials = { key: privateKey, cert: certificate, ca: ca };
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(limiter);

// Test database connection
sequelize.authenticate()
    .then(() => console.log('Database connected...'))
    .catch(err => console.log('Error: ' + err));

const projectRoutes = require('./routes/projectRoutes');
const taskRoutes = require('./routes/taskRoutes');
const userRoutes = require('./routes/userRoutes');

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

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
