const express = require('express');
const UserService = require('../services/userService');
const JWTUtils = require('../utils/jwt');
const ValidationUtils = require('../utils/validation');
const { authenticateToken } = require('../middleware/auth'); // Add this import

const router = express.Router();

// Sign up endpoint
router.post('/signup', async (req, res) => {
  try {
    const { email, password, full_name } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    if (!ValidationUtils.validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);

    // Check if email already exists
    const existingUser = await UserService.findByEmail(sanitizedEmail);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Create user
    const user = await UserService.createUser({
      email: sanitizedEmail,
      password,
      full_name
    });

    // Generate JWT token
    const token = JWTUtils.generateToken({
      userId: user.id,
      email: user.email
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user,
      token
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Sign in endpoint
router.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);
    const user = await UserService.findByEmail(sanitizedEmail);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const validPassword = await UserService.verifyPassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const token = JWTUtils.generateToken({
      userId: user.id,
      email: user.email
    });

    await UserService.updateLastLogin(user.id);

    res.status(200).json({
      success: true,
      message: 'Sign in successful',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name
      },
      token
    });

  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Unlink Google account endpoint
router.post('/unlink-google', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Check if user has a password (can't unlink if it's their only auth method)
    const user = await UserService.findById(userId);
    
    if (!user || !user.password_hash) {
      return res.status(400).json({
        success: false,
        message: 'Cannot unlink Google account. Please set a password first.'
      });
    }

    // Unlink Google account
    await UserService.unlinkGoogleAccount(userId);

    res.json({
      success: true,
      message: 'Google account unlinked successfully'
    });
  } catch (error) {
    console.error('Error unlinking Google account:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to unlink Google account'
    });
  }
});

// Check if user can sign in with Google
router.post('/check-google', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const user = await UserService.findByEmailWithGoogleInfo(email);

    res.json({
      success: true,
      hasGoogleAuth: !!user?.google_id,
      authProvider: user?.auth_provider || null
    });
  } catch (error) {
    res.json({
      success: true,
      hasGoogleAuth: false,
      authProvider: null
    });
  }
});

module.exports = router;