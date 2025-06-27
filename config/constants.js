
module.exports = {
  JWT_SECRET: process.env.JWT_SECRET || 'your-fallback-secret-key',
  OTP_EXPIRY_MINUTES: 10,
  OTP_LENGTH: 6,
  SALT_ROUNDS: 10,
  RATE_LIMIT_MS: 60 * 1000, // 1 minute
  FROM_EMAIL: process.env.FROM_EMAIL || 'noreply@yourdomain.com'
};
