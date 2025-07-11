const express = require('express');
const UserService = require('../services/userService');
const JWTUtils = require('../utils/jwt');
const ValidationUtils = require('../utils/validation');

const router = express.Router();

// Sign up endpoint
router.post('/signup', async (req, res) => {
  try {
    const { email, password, full_name } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Validate email format
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
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        profile_picture: user.profile_picture
      },
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

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);
    const user = await UserService.findByEmail(sanitizedEmail);

    // Check if user exists
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Verify password
    const validPassword = await UserService.verifyPassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = JWTUtils.generateToken({
      userId: user.id,
      email: user.email
    });

    // Update last login timestamp
    await UserService.updateLastLogin(user.id);

    res.status(200).json({
      success: true,
      message: 'Sign in successful',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        profile_picture: user.profile_picture
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

// ✅ NEW: Token verification endpoint
// This endpoint allows the frontend to verify if a stored token is still valid
router.get('/verify-token', async (req, res) => {
  try {
    // Extract the token from the Authorization header
    const authHeader = req.headers.authorization;
    
    // Check if the Authorization header exists and has the correct format
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided or invalid format'
      });
    }

    // Extract the actual token (remove "Bearer " prefix)
    const token = authHeader.split(' ')[1];

    // Verify the token using your JWT utility
    let decoded;
    try {
      decoded = JWTUtils.verifyToken(token);
    } catch (jwtError) {
      // Token is invalid or expired
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    // Check if the user still exists in the database
    // This is important in case the user was deleted after the token was issued
    const user = await UserService.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    // Token is valid and user exists, return user information
    res.status(200).json({
      success: true,
      message: 'Token is valid',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        profile_picture: user.profile_picture,
        last_login: user.last_login
      }
    });

  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during token verification'
    });
  }
});

// ✅ NEW: Logout endpoint (optional but recommended)
// While JWT tokens are stateless and logout is typically handled on the frontend,
// this endpoint can be useful for logging purposes or future token blacklisting
router.post('/logout', async (req, res) => {
  try {
    // Extract user info from token if available (for logging purposes)
    const authHeader = req.headers.authorization;
    let userInfo = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      try {
        const decoded = JWTUtils.verifyToken(token);
        const user = await UserService.findById(decoded.userId);
        userInfo = user ? { id: user.id, email: user.email } : null;
      } catch (error) {
        // Token might be invalid, but we still want to allow logout
        console.log('Invalid token during logout, but allowing logout to proceed');
      }
    }

    // Log the logout event (optional)
    if (userInfo) {
      console.log(`User ${userInfo.email} (ID: ${userInfo.id}) logged out at ${new Date().toISOString()}`);
    }

    // For JWT tokens, logout is typically handled on the frontend
    // by simply removing the token from storage
    // However, you could implement token blacklisting here if needed
    
    res.status(200).json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during logout'
    });
  }
});

// ✅ NEW: Get current user information
// This endpoint allows the frontend to get current user data
// It's similar to verify-token but focuses on returning user data
router.get('/me', async (req, res) => {
  try {
    // Extract the token from the Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided or invalid format'
      });
    }

    const token = authHeader.split(' ')[1];

    // Verify the token
    let decoded;
    try {
      decoded = JWTUtils.verifyToken(token);
    } catch (jwtError) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    // Get user information
    const user = await UserService.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    // Return comprehensive user information
    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        profile_picture: user.profile_picture,
        last_login: user.last_login,
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    });

  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// ✅ NEW: Refresh token endpoint (optional, for enhanced security)
// This endpoint allows clients to refresh their tokens before they expire
router.post('/refresh-token', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided or invalid format'
      });
    }

    const token = authHeader.split(' ')[1];

    // Verify the current token
    let decoded;
    try {
      decoded = JWTUtils.verifyToken(token);
    } catch (jwtError) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    // Check if user still exists
    const user = await UserService.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    // Generate a new token
    const newToken = JWTUtils.generateToken({
      userId: user.id,
      email: user.email
    });

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      token: newToken,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        profile_picture: user.profile_picture
      }
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during token refresh'
    });
  }
});

module.exports = router;