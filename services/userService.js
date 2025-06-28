const supabase = require('../config/database');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { SALT_ROUNDS } = require('../config/constants');

class UserService {
  // Existing email-based authentication methods
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
        auth_provider: 'email', // Added to distinguish auth methods
        created_at: new Date().toISOString()
      }])
      .select('id, email, full_name, auth_provider, created_at');

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
    const { error } = await supabase
      .from('profiles')
      .update({ last_login: new Date().toISOString() })
      .eq('id', userId);

    if (error) {
      throw error;
    }
  }

  // Google OAuth methods
  static async findUserByGoogleId(googleId) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('google_id', googleId)
        .single();

      if (error && error.code !== 'PGRST116') {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error finding user by Google ID:', error);
      throw error;
    }
  }

  static async linkGoogleAccount(userId, googleId, avatarUrl) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .update({
          google_id: googleId,
          auth_provider: 'google',
          avatar_url: avatarUrl,
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)
        .select()
        .single();

      if (error) {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error linking Google account:', error);
      throw error;
    }
  }

  static async createGoogleUser(email, googleId, fullName, avatarUrl) {
    try {
      const userId = crypto.randomUUID();
      
      const { data, error } = await supabase
        .from('profiles')
        .insert({
          id: userId,
          email: email.toLowerCase(),
          google_id: googleId,
          full_name: fullName,
          auth_provider: 'google',
          avatar_url: avatarUrl,
          created_at: new Date().toISOString(),
          last_login: new Date().toISOString()
        })
        .select()
        .single();

      if (error) {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error creating Google user:', error);
      throw error;
    }
  }

  // Enhanced user lookup method that supports both email and Google ID
  static async findUser(identifier, type = 'email') {
    try {
      let query = supabase.from('profiles').select('*');
      
      if (type === 'email') {
        query = query.eq('email', identifier.toLowerCase());
      } else if (type === 'google_id') {
        query = query.eq('google_id', identifier);
      } else if (type === 'id') {
        query = query.eq('id', identifier);
      } else {
        throw new Error('Invalid lookup type. Use "email", "google_id", or "id"');
      }

      const { data, error } = await query.single();

      if (error && error.code !== 'PGRST116') {
        throw error;
      }

      return data;
    } catch (error) {
      console.error(`Error finding user by ${type}:`, error);
      throw error;
    }
  }

  // Update user profile method
  static async updateProfile(userId, updates) {
    try {
      const allowedUpdates = ['full_name', 'avatar_url', 'updated_at'];
      const filteredUpdates = Object.keys(updates)
        .filter(key => allowedUpdates.includes(key))
        .reduce((obj, key) => {
          obj[key] = updates[key];
          return obj;
        }, {});

      filteredUpdates.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('profiles')
        .update(filteredUpdates)
        .eq('id', userId)
        .select('id, email, full_name, avatar_url, auth_provider')
        .single();

      if (error) {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error updating user profile:', error);
      throw error;
    }
  }

  // Check if user exists by email (useful for registration validation)
  static async userExists(email) {
    try {
      const user = await this.findByEmail(email);
      return !!user;
    } catch (error) {
      console.error('Error checking if user exists:', error);
      return false;
    }
  }

  // Soft delete user (mark as deleted instead of removing)
  static async deleteUser(userId) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .update({
          deleted_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)
        .select('id')
        .single();

      if (error) {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error deleting user:', error);
      throw error;
    }
  }
}

module.exports = UserService;