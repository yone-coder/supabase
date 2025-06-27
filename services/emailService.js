
const { Resend } = require('resend');
const { FROM_EMAIL, OTP_EXPIRY_MINUTES } = require('../config/constants');

const resend = new Resend(process.env.RESEND_API_KEY);

class EmailService {
  static async sendOTPEmail(email, otp, type = 'signin') {
    try {
      const subject = type === 'signin' ? 'Your Sign-In Code' : 'Your Verification Code';
      const html = this.getOTPEmailTemplate(otp, type);

      const { data, error } = await resend.emails.send({
        from: FROM_EMAIL,
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
  }

  static async sendPasswordResetEmail(email, otp) {
    try {
      const html = this.getPasswordResetEmailTemplate(otp);

      const { data, error } = await resend.emails.send({
        from: FROM_EMAIL,
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
  }

  static getOTPEmailTemplate(otp, type) {
    return `
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
  }

  static getPasswordResetEmailTemplate(otp) {
    return `
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
  }
}

module.exports = EmailService;
