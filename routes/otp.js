
const express = require('express');
const UserService = require('../services/userService');
const OTPService = require('../services/otpService');
const EmailService = require('../services/emailService');
const JWTUtils = require('../utils/jwt');
const ValidationUtils = require('../utils/validation');

const router = express.Router();

// Send OTP for email sign-in
router.post('/send-otp', async (req, res) => {
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

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Email not registered. Please sign up first.'
      });
    }

    // Check rate limiting
    const rateLimit = await OTPService.checkRateLimit(sanitizedEmail);
    if (rateLimit.limited) {
      return res.status(429).json({
        success: false,
        message: 'Please wait before requesting another OTP',
        retryAfter: rateLimit.retryAfter
      });
    }

    // Generate and store OTP
    const otp = OTPService.generateOTP();
    const { expiresIn } = await OTPService.storeOTP(sanitizedEmail, otp, 'signin');

    // Send OTP via email
    const emailResult = await EmailService.sendOTPEmail(sanitizedEmail, otp, 'signin');
    
    if (!emailResult.success) {
      return res.status(500).json({
        success: false,
        message: 'Failed to send OTP email',
        error: emailResult.error
      });
    }

    res.status(200).json({
      success: true,
      message: 'OTP sent successfully to your email',
      expiresIn
    });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Verify OTP and sign in
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required'
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);
    const verification = await OTPService.verifyOTP(sanitizedEmail, otp, 'signin');

    if (!verification.valid) {
      return res.status(401).json({
        success: false,
        message: verification.message
      });
    }

    const user = await UserService.findByEmail(sanitizedEmail);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const token = JWTUtils.generateToken({
      userId: user.id,
      email: user.email
    });

    await UserService.updateLastLogin(user.id);

    res.status(200).json({
      success: true,
      message: 'OTP verification successful',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name
      },
      token
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Request password reset
router.post('/request-password-reset', async (req, res) => {
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

    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If the email is registered, you will receive a password reset code shortly.'
      });
    }

    // Check rate limiting
    const rateLimit = await OTPService.checkRateLimit(sanitizedEmail, 'password_reset');
    if (rateLimit.limited) {
      return res.status(429).json({
        success: false,
        message: 'Please wait before requesting another password reset code',
        retryAfter: rateLimit.retryAfter
      });
    }

    // Generate and store OTP
    const otp = OTPService.generateOTP();
    const { expiresIn } = await OTPService.storeOTP(sanitizedEmail, otp, 'password_reset');

    // Send password reset email
    const emailResult = await EmailService.sendPasswordResetEmail(sanitizedEmail, otp);
    
    if (!emailResult.success) {
      return res.status(500).json({
        success: false,
        message: 'Failed to send password reset email'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Password reset code sent to your email',
      expiresIn
    });

  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});



// Add this new endpoint to your existing router

// Verify password reset OTP (without resetting password)
router.post('/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required'
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);
    const verification = await OTPService.verifyOTP(sanitizedEmail, otp, 'password_reset');

    if (!verification.valid) {
      return res.status(401).json({
        success: false,
        message: verification.message
      });
    }

    // OTP is valid, but don't consume it yet - it will be consumed during password reset
    res.status(200).json({
      success: true,
      message: 'OTP verification successful'
    });

  } catch (error) {
    console.error('Reset OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});



// Reset password with OTP
router.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email, OTP, and new password are required'
      });
    }

    if (!ValidationUtils.validatePassword(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    const sanitizedEmail = ValidationUtils.sanitizeEmail(email);
    const verification = await OTPService.verifyOTP(sanitizedEmail, otp, 'password_reset');

    if (!verification.valid) {
      return res.status(401).json({
        success: false,
        message: verification.message
      });
    }

    const updatedUser = await UserService.updatePasswordByEmail(sanitizedEmail, newPassword);
    
    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found or password update failed'
      });
    }

    const token = JWTUtils.generateToken({
      userId: updatedUser.id,
      email: updatedUser.email
    });

    await UserService.updateLastLogin(updatedUser.id);

    res.status(200).json({
      success: true,
      message: 'Password reset successful',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        full_name: updatedUser.full_name
      },
      token
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Clean up expired OTPs
router.post('/cleanup-otps', async (req, res) => {
  try {
    const deletedCount = await OTPService.cleanupExpiredOTPs();

    res.status(200).json({
      success: true,
      message: 'Expired OTPs cleaned up successfully',
      deletedCount
    });

  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

module.exports = router;
