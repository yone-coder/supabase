const supabase = require('../config/database');
const { OTP_EXPIRY_MINUTES, RATE_LIMIT_MS } = require('../config/constants');

class OTPService {
  // Generate a 6-digit numeric OTP
  static generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  // Store or update an OTP for a given email and purpose
  static async storeOTP(email, otp, purpose = 'signin') {
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    const { error } = await supabase
      .from('otp_codes')
      .upsert([{
        email: email.toLowerCase(),
        otp_code: otp,
        purpose,
        expires_at: expiresAt.toISOString(),
        created_at: new Date().toISOString(),
        used: false
      }], {
        onConflict: ['email', 'purpose'] // ✅ Make sure UNIQUE(email, purpose) exists in the DB
      });

    if (error) {
      throw error;
    }

    return { expiresAt, expiresIn: OTP_EXPIRY_MINUTES };
  }

  // Verify if the OTP is valid, not expired, and not used
  static async verifyOTP(email, otp, purpose = 'signin') {
    const { data: otpRecord, error } = await supabase
      .from('otp_codes')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('otp_code', otp)
      .eq('purpose', purpose)
      .eq('used', false)
      .single();

    if (error || !otpRecord) {
      return { valid: false, message: 'Invalid OTP code' };
    }

    const now = new Date();
    const expiresAt = new Date(otpRecord.expires_at);

    if (now > expiresAt) {
      await this.markOTPAsUsed(otpRecord.id);
      return { valid: false, message: 'OTP code has expired' };
    }

    await this.markOTPAsUsed(otpRecord.id);
    return { valid: true, otpRecord };
  }

  // Mark the OTP as used
  static async markOTPAsUsed(otpId) {
    await supabase
      .from('otp_codes')
      .update({ used: true })
      .eq('id', otpId);
  }

  // Prevent OTP spamming — only allow one OTP per X seconds
  static async checkRateLimit(email, purpose = 'signin') {
    const { data: lastOtp } = await supabase
      .from('otp_codes')
      .select('created_at')
      .eq('email', email.toLowerCase())
      .eq('purpose', purpose)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (lastOtp) {
      const timeSinceLastOtp = Date.now() - new Date(lastOtp.created_at).getTime();

      if (timeSinceLastOtp < RATE_LIMIT_MS) {
        return {
          limited: true,
          retryAfter: Math.ceil((RATE_LIMIT_MS - timeSinceLastOtp) / 1000)
        };
      }
    }

    return { limited: false };
  }

  // Clean up old OTPs after expiry
  static async cleanupExpiredOTPs() {
    const { data, error } = await supabase
      .from('otp_codes')
      .delete()
      .lt('expires_at', new Date().toISOString());

    if (error) {
      throw error;
    }

    return data?.length || 0;
  }
}

module.exports = OTPService;