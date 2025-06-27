
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/constants');

class JWTUtils {
  static generateToken(payload, expiresIn = '24h') {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
  }

  static verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
  }
}

module.exports = JWTUtils;
