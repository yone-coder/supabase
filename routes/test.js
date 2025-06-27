
const express = require('express');
const supabase = require('../config/database');
const UserService = require('../services/userService');
const OTPService = require('../services/otpService');
const crypto = require('crypto');

const router = express.Router();

// Test database connection
router.get('/test-db', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .limit(1);

    if (error) {
      return res.status(500).json({
        success: false,
        message: 'Database connection failed',
        error: error.message
      });
    }

    res.status(200).json({
      success: true,
      message: 'Database connection successful',
      columns: data && data.length > 0 ? Object.keys(data[0]) : [],
      sampleData: data
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Database test failed',
      error: error.message
    });
  }
});

// Debug OTP functionality
router.post('/debug-otp', async (req, res) => {
  try {
    console.log('=== Debug OTP Insert Test ===');
    
    // Test OTP generation and storage
    const testEmail = 'debug@test.com';
    const otp = OTPService.generateOTP();
    
    console.log('Generated OTP:', otp);
    
    const { expiresAt } = await OTPService.storeOTP(testEmail, otp, 'test');
    console.log('✓ OTP stored successfully');

    // Test verification
    const verification = await OTPService.verifyOTP(testEmail, otp, 'test');
    console.log('✓ OTP verification result:', verification);

    // Cleanup
    await supabase
      .from('otp_codes')
      .delete()
      .eq('email', testEmail);

    res.json({
      success: true,
      message: 'OTP debug test completed successfully',
      results: {
        otp,
        expiresAt,
        verification
      }
    });

  } catch (error) {
    console.error('Debug endpoint error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Check OTP table
router.get('/check-otp-table', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('otp_codes')
      .select('*')
      .limit(5);

    if (error) {
      return res.status(500).json({
        success: false,
        error: error
      });
    }

    res.json({
      success: true,
      message: 'OTP table info',
      sampleData: data,
      rowCount: data.length
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Add test email
router.post('/add-test-email', async (req, res) => {
  try {
    const { email, full_name } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const user = await UserService.createUser({
      email,
      password: 'test123',
      full_name: full_name || 'Test User'
    });

    res.status(200).json({
      success: true,
      message: 'Test email added successfully',
      data: user
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// List all emails
router.get('/list-emails', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('id, email, full_name, created_at')
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({
        success: false,
        error: error.message
      });
    }

    res.status(200).json({
      success: true,
      emails: data,
      count: data.length
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
