const express = require('express');
const passport = require('../config/passport');
const { generateToken } = require('../utils/jwt');
const router = express.Router();

// Initiate Google OAuth
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'] 
  })
);

// Google OAuth callback
router.get('/google/callback',
  passport.authenticate('google', { 
    failureRedirect: process.env.CLIENT_URL + '/signin?error=oauth_failed' 
  }),
  async (req, res) => {
    try {
      // Generate JWT token
      const token = generateToken(req.user.id);
      
      // Redirect to frontend with token
      const redirectUrl = `${process.env.CLIENT_URL}/auth/callback?token=${token}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      res.redirect(process.env.CLIENT_URL + '/signin?error=oauth_callback_failed');
    }
  }
);

// Get Google OAuth URL (for frontend)
router.get('/google/url', (req, res) => {
  const authUrl = `${req.protocol}://${req.get('host')}/api/auth/google`;
  res.json({ url: authUrl });
});

module.exports = router;