// server.js - Express.js server with OTP email authentication
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Supabase setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Resend setup
const resend = new Resend(process.env.RESEND_API_KEY);

// JWT secret - add this to your environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key';

// OTP configuration
const OTP_EXPIRY_MINUTES = 10; // OTP expires in 10 minutes
const OTP_LENGTH = 6; // 6-digit OTP

// Middleware - CORS configuration to accept calls from anywhere
app.use(cors({
  origin: '*', // Allow requests from any origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: false // Set to false when using origin: '*'
}));
app.use(express.json());

// Handle preflight OPTIONS requests
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.sendStatus(200);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Utility function to generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
};

// Utility function to send OTP email
const sendOTPEmail = async (email, otp, type = 'signin') => {
  try {
    const subject = type === 'signin' ? 'Your Sign-In Code' : 'Your Verification Code';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333; text-align: center;">Your Verification Code</h2>
        <div style="background-color: #f8f9fa; border-radius: 8px; padding: 30px; text-align: center; margin: 20px 0;">
          <h1 style="color: #007bff; font-size: 36px; margin: 0; letter-spacing: 5px;">${otp}</h1>
        </div>
        <p style="color: #666; text-align: center; margin: 20px 0;">
          Enter this code to ${type === 'signin' ? 'sign in to' : 'verify'} your account.
        </p>
        <p style="color: #999; font-size: 14px; text-align: center;">
          This code expires in ${OTP_EXPIRY_MINUTES} minutes. If you didn't request this code, please ignore this email.
        </p>
      </div>
    `;

    const { data, error } = await resend.emails.send({
      from: process.env.FROM_EMAIL || 'noreply@yourdomain.com', // Update with your verified domain
      to: [email],
      subject: subject,
      html: html,
    });

    if (error) {
      console.error('Resend error:', error);
      return { success: false, error };
    }

    return { success: true, data };
  } catch (error) {
    console.error('Email sending error:', error);
    return { success: false, error };
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// Test database connection
app.get('/api/test-db', async (req, res) => {
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

// Sign up endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, full_name } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Check if email already exists
    const { data: existingUser } = await supabase
      .from('profiles')
      .select('email')
      .eq('email', email.toLowerCase())
      .single();

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = crypto.randomUUID();
    const { data, error } = await supabase
      .from('profiles')
      .insert([{
        id: userId,
        email: email.toLowerCase(),
        password_hash: hashedPassword,
        full_name: full_name || null,
        created_at: new Date().toISOString()
      }])
      .select('id, email, full_name, created_at');

    if (error) {
      return res.status(500).json({
        success: false,
        message: 'Failed to create user',
        error: error.message
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: userId, email: email.toLowerCase() },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: data[0],
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

// Sign in endpoint (traditional password)
app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user by email
    const { data: user, error } = await supabase
      .from('profiles')
      .select('id, email, password_hash, full_name')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Update last login
    await supabase
      .from('profiles')
      .update({ last_login: new Date().toISOString() })
      .eq('id', user.id);

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

// NEW: Send OTP for email sign-in
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Check if user exists
    const { data: user, error } = await supabase
      .from('profiles')
      .select('id, email, full_name')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(404).json({
        success: false,
        message: 'Email not registered. Please sign up first.'
      });
    }

    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    // Store OTP in database (you'll need to create an otp_codes table)
    const { error: otpError } = await supabase
      .from('otp_codes')
      .upsert([{
        email: email.toLowerCase(),
        otp_code: otp,
        expires_at: expiresAt.toISOString(),
        created_at: new Date().toISOString(),
        used: false
      }], { onConflict: 'email' });

    if (otpError) {
      console.error('OTP storage error:', otpError);
      return res.status(500).json({
        success: false,
        message: 'Failed to generate OTP'
      });
    }

    // Send OTP via email
    const emailResult = await sendOTPEmail(email, otp, 'signin');
    
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
      expiresIn: OTP_EXPIRY_MINUTES
    });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// NEW: Verify OTP and sign in
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required'
      });
    }

    // Get stored OTP
    const { data: otpRecord, error: otpError } = await supabase
      .from('otp_codes')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('otp_code', otp)
      .eq('used', false)
      .single();

    if (otpError || !otpRecord) {
      return res.status(401).json({
        success: false,
        message: 'Invalid OTP code'
      });
    }

    // Check if OTP is expired
    const now = new Date();
    const expiresAt = new Date(otpRecord.expires_at);
    
    if (now > expiresAt) {
      // Mark OTP as used to prevent reuse
      await supabase
        .from('otp_codes')
        .update({ used: true })
        .eq('email', email.toLowerCase());

      return res.status(401).json({
        success: false,
        message: 'OTP code has expired'
      });
    }

    // Mark OTP as used
    await supabase
      .from('otp_codes')
      .update({ used: true })
      .eq('email', email.toLowerCase());

    // Get user details
    const { data: user, error: userError } = await supabase
      .from('profiles')
      .select('id, email, full_name')
      .eq('email', email.toLowerCase())
      .single();

    if (userError || !user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Update last login
    await supabase
      .from('profiles')
      .update({ last_login: new Date().toISOString() })
      .eq('id', user.id);

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

// NEW: Resend OTP
app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Check rate limiting - prevent too frequent requests
    const { data: lastOtp } = await supabase
      .from('otp_codes')
      .select('created_at')
      .eq('email', email.toLowerCase())
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (lastOtp) {
      const timeSinceLastOtp = Date.now() - new Date(lastOtp.created_at).getTime();
      const rateLimitMs = 60 * 1000; // 1 minute rate limit

      if (timeSinceLastOtp < rateLimitMs) {
        return res.status(429).json({
          success: false,
          message: 'Please wait before requesting another OTP',
          retryAfter: Math.ceil((rateLimitMs - timeSinceLastOtp) / 1000)
        });
      }
    }

    // Use the same logic as send-otp
    return app._router.handle({ ...req, url: '/api/send-otp', method: 'POST' }, res);

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get current user profile (protected route)
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('profiles')
      .select('id, email, full_name, created_at, last_login')
      .eq('id', req.user.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      user
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add password to existing user (for migration/setup)
app.post('/api/set-password', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Hash the new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Update the user's password
    const { data, error } = await supabase
      .from('profiles')
      .update({ 
        password_hash: hashedPassword,
        updated_at: new Date().toISOString()
      })
      .eq('email', email.toLowerCase())
      .select('id, email, full_name');

    if (error) {
      return res.status(500).json({
        success: false,
        message: 'Failed to update password',
        error: error.message
      });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Password set successfully',
      user: data[0]
    });

  } catch (error) {
    console.error('Set password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Temporary endpoint to migrate users without passwords
app.post('/api/migrate-user', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }
    
    // Check if user exists and has no password
    const { data: user, error: fetchError } = await supabase
      .from('profiles')
      .select('id, email, password_hash, full_name')
      .eq('email', email.toLowerCase())
      .single();
      
    if (fetchError || !user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    if (user.password_hash) {
      return res.status(400).json({ 
        success: false, 
        message: 'User already has password. Use sign in instead.' 
      });
    }
    
    // Set password
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('profiles')
      .update({ 
        password_hash: hashedPassword,
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id)
      .select('id, email, full_name');
      
    if (error) {
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to set password',
        error: error.message 
      });
    }
    
    // Generate JWT token for immediate login
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(200).json({ 
      success: true, 
      message: 'Password added successfully. User can now sign in.',
      user: data[0],
      token
    });
    
  } catch (error) {
    console.error('Migration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      error: error.message 
    });
  }
});




// Add these endpoints to your existing server.js file

// NEW: Request password reset (sends OTP via email)
app.post('/api/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Check if user exists
    const { data: user, error } = await supabase
      .from('profiles')
      .select('id, email, full_name')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      // For security, don't reveal if email exists or not
      return res.status(200).json({
        success: true,
        message: 'If the email is registered, you will receive a password reset code shortly.',
        expiresIn: OTP_EXPIRY_MINUTES
      });
    }

    // Check rate limiting - prevent too frequent requests
    const { data: lastOtp } = await supabase
      .from('otp_codes')
      .select('created_at, purpose')
      .eq('email', email.toLowerCase())
      .eq('purpose', 'password_reset')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (lastOtp) {
      const timeSinceLastOtp = Date.now() - new Date(lastOtp.created_at).getTime();
      const rateLimitMs = 60 * 1000; // 1 minute rate limit

      if (timeSinceLastOtp < rateLimitMs) {
        return res.status(429).json({
          success: false,
          message: 'Please wait before requesting another password reset code',
          retryAfter: Math.ceil((rateLimitMs - timeSinceLastOtp) / 1000)
        });
      }
    }

    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    // Store OTP in database with password reset purpose
    const { error: otpError } = await supabase
      .from('otp_codes')
      .insert([{
        email: email.toLowerCase(),
        otp_code: otp,
        purpose: 'password_reset', // Add purpose field to distinguish from signin OTPs
        expires_at: expiresAt.toISOString(),
        created_at: new Date().toISOString(),
        used: false
      }]);

    if (otpError) {
      console.error('OTP storage error:', otpError);
      return res.status(500).json({
        success: false,
        message: 'Failed to generate password reset code'
      });
    }

    // Send OTP via email with password reset context
    const emailResult = await sendPasswordResetEmail(email, otp);
    
    if (!emailResult.success) {
      return res.status(500).json({
        success: false,
        message: 'Failed to send password reset email',
        error: emailResult.error
      });
    }

    res.status(200).json({
      success: true,
      message: 'Password reset code sent to your email',
      expiresIn: OTP_EXPIRY_MINUTES
    });

  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// NEW: Reset password with OTP verification
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email, OTP, and new password are required'
      });
    }

    // Validate password strength (add your own rules)
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Get stored OTP for password reset
    const { data: otpRecord, error: otpError } = await supabase
      .from('otp_codes')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('otp_code', otp)
      .eq('purpose', 'password_reset')
      .eq('used', false)
      .single();

    if (otpError || !otpRecord) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password reset code'
      });
    }

    // Check if OTP is expired
    const now = new Date();
    const expiresAt = new Date(otpRecord.expires_at);
    
    if (now > expiresAt) {
      // Mark OTP as used to prevent reuse
      await supabase
        .from('otp_codes')
        .update({ used: true })
        .eq('id', otpRecord.id);

      return res.status(401).json({
        success: false,
        message: 'Password reset code has expired'
      });
    }

    // Mark OTP as used
    await supabase
      .from('otp_codes')
      .update({ used: true })
      .eq('id', otpRecord.id);

    // Hash the new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update user's password
    const { data: updatedUser, error: updateError } = await supabase
      .from('profiles')
      .update({ 
        password_hash: hashedPassword,
        updated_at: new Date().toISOString()
      })
      .eq('email', email.toLowerCase())
      .select('id, email, full_name');

    if (updateError || !updatedUser || updatedUser.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found or password update failed'
      });
    }

    // Generate JWT token for immediate login (optional)
    const token = jwt.sign(
      { userId: updatedUser[0].id, email: updatedUser[0].email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Update last login
    await supabase
      .from('profiles')
      .update({ last_login: new Date().toISOString() })
      .eq('id', updatedUser[0].id);

    res.status(200).json({
      success: true,
      message: 'Password reset successful',
      user: {
        id: updatedUser[0].id,
        email: updatedUser[0].email,
        full_name: updatedUser[0].full_name
      },
      token // Include token to automatically sign user in
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// NEW: Utility function to send password reset email
const sendPasswordResetEmail = async (email, otp) => {
  try {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333; text-align: center;">Password Reset Request</h2>
        <p style="color: #666; text-align: center; margin: 20px 0;">
          We received a request to reset your password. Use the code below to set a new password:
        </p>
        <div style="background-color: #f8f9fa; border-radius: 8px; padding: 30px; text-align: center; margin: 20px 0;">
          <h1 style="color: #dc3545; font-size: 36px; margin: 0; letter-spacing: 5px;">${otp}</h1>
        </div>
        <p style="color: #666; text-align: center; margin: 20px 0;">
          Enter this code along with your new password to complete the reset process.
        </p>
        <p style="color: #999; font-size: 14px; text-align: center;">
          This code expires in ${OTP_EXPIRY_MINUTES} minutes. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
        </p>
        <div style="border-top: 1px solid #eee; margin-top: 30px; padding-top: 20px;">
          <p style="color: #999; font-size: 12px; text-align: center;">
            For security reasons, this code can only be used once. If you need a new code, please request another password reset.
          </p>
        </div>
      </div>
    `;

    const { data, error } = await resend.emails.send({
      from: process.env.FROM_EMAIL || 'noreply@yourdomain.com',
      to: [email],
      subject: 'Password Reset Code',
      html: html,
    });

    if (error) {
      console.error('Resend error:', error);
      return { success: false, error };
    }

    return { success: true, data };
  } catch (error) {
    console.error('Password reset email sending error:', error);
    return { success: false, error };
  }
};






// Add this temporary endpoint to your server.js for debugging
app.post('/api/debug-otp', async (req, res) => {
  try {
    console.log('=== Debug OTP Insert Test ===');
    
    // Test 1: Simple select to verify table exists
    console.log('Test 1: Checking if otp_codes table exists...');
    const { data: tableTest, error: tableError } = await supabase
      .from('otp_codes')
      .select('*')
      .limit(1);
    
    if (tableError) {
      console.error('Table test error:', tableError);
      return res.status(500).json({
        success: false,
        step: 'table_check',
        error: tableError
      });
    }
    console.log('✓ Table exists and is accessible');

    // Test 2: Simple insert
    console.log('Test 2: Attempting simple insert...');
    const testOtp = {
      email: 'debug@test.com',
      otp_code: '123456',
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      created_at: new Date().toISOString(),
      used: false
    };
    
    console.log('Test data:', testOtp);
    
    const { data: insertData, error: insertError } = await supabase
      .from('otp_codes')
      .insert([testOtp])
      .select();
    
    if (insertError) {
      console.error('Insert test error:', insertError);
      return res.status(500).json({
        success: false,
        step: 'insert_test',
        error: insertError,
        testData: testOtp
      });
    }
    console.log('✓ Insert successful:', insertData);

    // Test 3: Upsert (like the real endpoint does)
    console.log('Test 3: Testing upsert...');
    const upsertOtp = {
      email: 'debug@test.com', // Same email to test upsert
      otp_code: '654321',
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      created_at: new Date().toISOString(),
      used: false
    };
    
    const { data: upsertData, error: upsertError } = await supabase
      .from('otp_codes')
      .upsert([upsertOtp], { onConflict: 'email' })
      .select();
    
    if (upsertError) {
      console.error('Upsert test error:', upsertError);
      return res.status(500).json({
        success: false,
        step: 'upsert_test',
        error: upsertError,
        testData: upsertOtp
      });
    }
    console.log('✓ Upsert successful:', upsertData);

    // Cleanup
    await supabase
      .from('otp_codes')
      .delete()
      .eq('email', 'debug@test.com');

    res.json({
      success: true,
      message: 'All OTP database tests passed',
      results: {
        tableExists: true,
        insertWorked: true,
        upsertWorked: true,
        insertData,
        upsertData
      }
    });

  } catch (error) {
    console.error('Debug endpoint error:', error);
    res.status(500).json({
      success: false,
      step: 'catch_block',
      error: error.message,
      stack: error.stack
    });
  }
});

// Also add this endpoint to check your table structure
app.get('/api/check-otp-table', async (req, res) => {
  try {
    // Get some info about the table
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

// Email check endpoint
app.post('/api/check-email', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email format' 
      });
    }

    // Check if email exists in your profiles table
    const { data, error } = await supabase
      .from('profiles') 
      .select('email')
      .eq('email', email.toLowerCase())
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 is "not found" error
      console.error('Supabase error:', error);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error',
        error: error.message
      });
    }

    const exists = data !== null;

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

// Add a test email to your profiles table (for testing)
app.post('/api/add-test-email', async (req, res) => {
  try {
    const { email, full_name } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const { data, error } = await supabase
      .from('profiles')
      .insert([
        { 
          id: crypto.randomUUID(),
          email: email.toLowerCase(),
          full_name: full_name || 'Test User'
        }
      ])
      .select();

    if (error) {
      return res.status(500).json({
        success: false,
        message: 'Failed to add test email',
        error: error.message
      });
    }

    res.status(200).json({
      success: true,
      message: 'Test email added successfully',
      data: data
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// List all emails in profiles table (for testing)
app.get('/api/list-emails', async (req, res) => {
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

// NEW: Clean up expired OTPs (maintenance endpoint)
app.post('/api/cleanup-otps', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('otp_codes')
      .delete()
      .lt('expires_at', new Date().toISOString());

    if (error) {
      return res.status(500).json({
        success: false,
        message: 'Failed to cleanup expired OTPs',
        error: error.message
      });
    }

    res.status(200).json({
      success: true,
      message: 'Expired OTPs cleaned up successfully',
      deletedCount: data?.length || 0
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!' 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
