const supabase = require('../config/database');
const { OTP_EXPIRY_MINUTES, RATE_LIMIT_MS } = require('../config/constants');
const bcrypt = require('bcryptjs');

class OTPService {
  // Generate a 6-digit numeric OTP
  static generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  // Store or update an OTP for a given email and purpose
  static async storeOTP(email, otp, purpose = 'signin') {
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
    
    // Hash the OTP before storing
    const otpHash = await bcrypt.hash(otp, 10);

    const { error } = await supabase
      .from('otp_codes')
      .upsert([{
        email: email.toLowerCase(),
        otp_hash: otpHash, // Store hash instead of plain OTP
        otp_code: otp, // Consider removing this column for better security
        purpose,
        expires_at: expiresAt.toISOString(),
        created_at: new Date().toISOString(),
        used: false
      }], {
        onConflict: ['email', 'purpose']
      });

    if (error) {
      throw error;
    }

    return { expiresAt, expiresIn: OTP_EXPIRY_MINUTES };
  }

  // Verify OTP without marking it as used
  static async verifyOTPWithoutConsuming(email, otp, purpose = 'signin') {
    const { data: otpRecord, error } = await supabase
      .from('otp_codes')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('purpose', purpose)
      .eq('used', false)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !otpRecord) {
      return { valid: false, message: 'Invalid OTP code' };
    }

    // Compare OTP securely
    const isValid = await bcrypt.compare(otp, otpRecord.otp_hash);
    if (!isValid) {
      return { valid: false, message: 'Invalid OTP code' };
    }

    const now = new Date();
    const expiresAt = new Date(otpRecord.expires_at);

    if (now > expiresAt) {
      return { valid: false, message: 'OTP code has expired' };
    }

    return { 
      valid: true, 
      otpRecord,
      // Optionally generate a verification token for next steps
      token: this.generateVerificationToken(email, purpose) 
    };
  }

  // Original verifyOTP that consumes the OTP
  static async verifyOTP(email, otp, purpose = 'signin') {
    const verification = await this.verifyOTPWithoutConsuming(email, otp, purpose);
    
    if (!verification.valid) {
      return verification;
    }

    // Mark as used only after successful verification
    await this.markOTPAsUsed(verification.otpRecord.id);
    return verification;
  }

  // Generate a JWT for OTP verification state
  static generateVerificationToken(email, purpose) {
    // Implement JWT generation here
    // Include email, purpose, and expiration
    return 'generated-jwt-token';
  }

  // Mark the OTP as used
  static async markOTPAsUsed(otpId) {
    const { error } = await supabase
      .from('otp_codes')
      .update({ used: true })
      .eq('id', otpId);

    if (error) {
      console.error('Error marking OTP as used:', error);
      throw error;
    }
  }

  // Prevent OTP spamming
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
      console.error('Error cleaning up expired OTPs:', error);
      throw error;
    }

    return data?.length || 0;
  }
}

module.exports = OTPService;