
class ValidationUtils {
  static validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static validatePassword(password, minLength = 6) {
    return password && password.length >= minLength;
  }

  static sanitizeEmail(email) {
    return email.toLowerCase().trim();
  }
}

module.exports = ValidationUtils;
