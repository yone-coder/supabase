const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Import middleware
const { corsMiddleware, jsonMiddleware, optionsMiddleware } = require('./middleware/cors');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandlers');

// Import routes
const authRoutes = require('./routes/auth');
const otpRoutes = require('./routes/otp');
const userRoutes = require('./routes/user');
const testRoutes = require('./routes/test');

const app = express();
const PORT = process.env.PORT || 3001;

// Apply middleware
corsMiddleware(app);
jsonMiddleware(app);
optionsMiddleware(app);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// Apply routes
app.use('/api', authRoutes);
app.use('/api', otpRoutes);
app.use('/api', userRoutes);
app.use('/api', testRoutes);

// Apply error handlers
app.use(errorHandler);
app.use(notFoundHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;