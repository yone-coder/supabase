
const supabase = require('../config/database');
const { OTP_EXPIRY_MINUTES, RATE_LIMIT_MS } = require('../config/constants');

class OTPService {
  static generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

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
      }], { onConflict: 'email' });

    if (error) {
      throw error;
    }

    return { expiresAt, expiresIn: OTP_EXPIRY_MINUTES };
  }

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

  static async markOTPAsUsed(otpId) {
    await supabase
      .from('otp_codes')
      .update({ used: true })
      .eq('id', otpId);
  }

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
