// server.js - Express.js server for Render.com with enhanced debugging
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Supabase setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

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

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// Database connection test endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    console.log('Testing database connection...');
    console.log('Supabase URL:', supabaseUrl ? 'Set' : 'Missing');
    console.log('Supabase Key:', supabaseKey ? 'Set' : 'Missing');

    if (!supabaseUrl || !supabaseKey) {
      return res.status(500).json({
        success: false,
        message: 'Missing environment variables',
        details: {
          supabaseUrl: !!supabaseUrl,
          supabaseKey: !!supabaseKey
        }
      });
    }

    // Test basic connection
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .limit(1);

    if (error) {
      console.error('Database test error:', error);
      return res.status(500).json({
        success: false,
        message: 'Database connection failed',
        error: {
          message: error.message,
          code: error.code,
          details: error.details,
          hint: error.hint
        }
      });
    }

    res.status(200).json({
      success: true,
      message: 'Database connection successful',
      tableExists: true,
      sampleData: data,
      recordCount: data ? data.length : 0
    });

  } catch (error) {
    console.error('Database test catch error:', error);
    res.status(500).json({
      success: false,
      message: 'Database test failed',
      error: error.message
    });
  }
});

// List available tables endpoint
app.get('/api/list-tables', async (req, res) => {
  try {
    const { data, error } = await supabase
      .rpc('get_table_list');

    if (error) {
      // Fallback method
      const { data: fallbackData, error: fallbackError } = await supabase
        .from('information_schema.tables')
        .select('table_name')
        .eq('table_schema', 'public');

      if (fallbackError) {
        return res.status(500).json({
          success: false,
          message: 'Cannot list tables',
          error: fallbackError.message
        });
      }

      return res.status(200).json({
        success: true,
        tables: fallbackData.map(t => t.table_name)
      });
    }

    res.status(200).json({
      success: true,
      tables: data
    });

  } catch (error) {
    console.error('List tables error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list tables',
      error: error.message
    });
  }
});

// Enhanced email check endpoint with debugging
app.post('/api/check-email', async (req, res) => {
  try {
    const { email } = req.body;

    console.log('=== EMAIL CHECK REQUEST ===');
    console.log('Request body:', req.body);
    console.log('Email received:', email);
    console.log('Supabase URL:', supabaseUrl ? 'Set' : 'Missing');
    console.log('Supabase Key:', supabaseKey ? 'Set' : 'Missing');

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

    // Check environment variables
    if (!supabaseUrl || !supabaseKey) {
      console.error('Missing environment variables');
      return res.status(500).json({
        success: false,
        message: 'Server configuration error',
        details: 'Missing database credentials'
      });
    }

    // Test basic table access first
    console.log('Testing table access...');
    const { data: testData, error: testError } = await supabase
      .from('profiles')
      .select('*')
      .limit(1);

    if (testError) {
      console.error('Table access error:', {
        message: testError.message,
        code: testError.code,
        details: testError.details,
        hint: testError.hint
      });
      
      return res.status(500).json({ 
        success: false, 
        message: 'Database table error',
        error: {
          message: testError.message,
          code: testError.code,
          hint: testError.hint
        }
      });
    }

    console.log('Table access successful. Sample data:', testData);

    // Now check for the specific email
    console.log('Searching for email:', email.toLowerCase());
    const { data, error } = await supabase
      .from('profiles')
      .select('email')
      .eq('email', email.toLowerCase())
      .single();

    console.log('Query result - Data:', data);
    console.log('Query result - Error:', error);

    if (error) {
      console.error('Email search error:', {
        message: error.message,
        code: error.code,
        details: error.details,
        hint: error.hint
      });

      // Only return 500 for actual errors, not "not found"
      if (error.code !== 'PGRST116') {
        return res.status(500).json({ 
          success: false, 
          message: 'Database query error',
          error: {
            message: error.message,
            code: error.code,
            hint: error.hint
          }
        });
      }
    }

    const exists = data !== null;
    console.log('Email exists:', exists);

    res.status(200).json({ 
      success: true, 
      exists,
      message: exists ? 'Email found' : 'Email not registered'
    });

  } catch (error) {
    console.error('Email check catch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Alternative email check with different approach
app.post('/api/check-email-alt', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    // Try without .single() to avoid PGRST116 error
    const { data, error } = await supabase
      .from('profiles')
      .select('email')
      .eq('email', email.toLowerCase());

    if (error) {
      console.error('Alternative email check error:', error);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error',
        error: error.message
      });
    }

    const exists = data && data.length > 0;

    res.status(200).json({ 
      success: true, 
      exists,
      message: exists ? 'Email found' : 'Email not registered',
      count: data ? data.length : 0
    });

  } catch (error) {
    console.error('Alternative email check error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
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
  console.log('Environment check:');
  console.log('- SUPABASE_URL:', supabaseUrl ? 'Set' : 'Missing');
  console.log('- SUPABASE_SERVICE_ROLE_KEY:', supabaseKey ? 'Set' : 'Missing');
});

module.exports = app;