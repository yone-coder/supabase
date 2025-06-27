
const supabase = require('../config/database');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { SALT_ROUNDS } = require('../config/constants');

class UserService {
  static async findByEmail(email) {
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();
    
    if (error && error.code !== 'PGRST116') {
      throw error;
    }
    
    return data;
  }

  static async createUser(userData) {
    const { email, password, full_name } = userData;
    const userId = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

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
      throw error;
    }

    return data[0];
  }

  static async verifyPassword(password, hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
  }

  static async updatePassword(userId, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    const { data, error } = await supabase
      .from('profiles')
      .update({ 
        password_hash: hashedPassword,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId)
      .select('id, email, full_name');

    if (error) {
      throw error;
    }

    return data[0];
  }

  static async updatePasswordByEmail(email, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    const { data, error } = await supabase
      .from('profiles')
      .update({ 
        password_hash: hashedPassword,
        updated_at: new Date().toISOString()
      })
      .eq('email', email.toLowerCase())
      .select('id, email, full_name');

    if (error) {
      throw error;
    }

    return data[0];
  }

  static async updateLastLogin(userId) {
    await supabase
      .from('profiles')
      .update({ last_login: new Date().toISOString() })
      .eq('id', userId);
  }
}

module.exports = UserService;
