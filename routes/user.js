
const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const UserService = require('../services/userService');
const ValidationUtils = require('../utils/validation');

const router = express.Router();

// Get current user profile (protected route)
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await UserService.findByEmail(req.user.email);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Remove sensitive data
    const { password_hash, ...userProfile } = user;

    res.status(200).json({
      success: true,
      user: userProfile
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Set password for existing user
router.post('/set-password', async (req, res) => {
  try {
    const { email, password } = req.body;

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
    const updatedUser = await UserService.updatePasswordByEmail(sanitizedEmail, password);

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Password set successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Set password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Check if email exists
router.post('/check-email', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    if (!ValidationUtils.validateEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email format' 
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);
    const user = await UserService.findByEmail(sanitizedEmail);
    const exists = !!user;

    res.status(200).json({ 
      success: true, 
      exists,
      message: exists ? 'Email found' : 'Email not registered'
    });

  } catch (error) {
    console.error('Email check error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error'
    });
  }
});

module.exports = router;
