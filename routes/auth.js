const express = require('express');
const UserService = require('../services/userService');
const JWTUtils = require('../utils/jwt');
const ValidationUtils = require('../utils/validation');

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

module.exports = router;