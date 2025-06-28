const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('./config/passport'); // Import configured passport
require('dotenv').config();

// Import middleware
const { corsMiddleware, jsonMiddleware, optionsMiddleware } = require('./middleware/cors');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandlers');

// Import routes
const authRoutes = require('./routes/auth');
const otpRoutes = require('./routes/otp');
const userRoutes = require('./routes/user');
const testRoutes = require('./routes/test');
const googleAuthRoutes = require('./routes/googleAuth');

const app = express();
const PORT = process.env.PORT || 3001;

// Session middleware (required for Passport) - must come before passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Apply other middleware
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
app.use('/api/auth', googleAuthRoutes); // Google OAuth routes

// Apply error handlers
app.use(errorHandler);
app.use(notFoundHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;