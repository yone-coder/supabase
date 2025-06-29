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

  static async findById(id) {
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', id)
      .single();

    if (error && error.code !== 'PGRST116') {
      throw error;
    }

    return data;
  }

  static async findByEmailWithGoogleInfo(email) {
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
        auth_provider: 'email',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select('id, email, full_name, profile_picture, auth_provider, created_at');

    if (error) {
      throw error;
    }

    return data[0];
  }

  static async createUserWithGoogle(userData) {
    try {
      const userId = crypto.randomUUID();
      
      const { data, error } = await supabase
        .from('profiles')
        .insert([{
          id: userId,
          email: userData.email.toLowerCase(),
          full_name: userData.full_name,
          google_id: userData.google_id,
          google_access_token: userData.google_access_token,
          profile_picture: userData.profile_picture,
          auth_provider: userData.auth_provider || 'google',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }])
        .select('id, email, full_name, profile_picture, auth_provider, created_at');

      if (error) {
        throw error;
      }

      return data[0];
    } catch (error) {
      console.error('Error creating user with Google:', error);
      throw error;
    }
  }

  static async linkGoogleAccount(userId, googleData) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .update({
          google_id: googleData.google_id,
          google_access_token: googleData.google_access_token,
          profile_picture: googleData.profile_picture,
          auth_provider: 'both', // User can now sign in with both email and Google
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)
        .select('id, email, full_name, profile_picture, auth_provider, updated_at');

      if (error) {
        throw error;
      }
      
      return data[0];
    } catch (error) {
      console.error('Error linking Google account:', error);
      throw error;
    }
  }

  static async unlinkGoogleAccount(userId) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .update({
          google_id: null,
          google_access_token: null,
          auth_provider: 'email', // fallback to email auth only
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)
        .select('id, email, full_name, profile_picture, auth_provider, updated_at');

      if (error) {
        throw error;
      }
      
      return data[0];
    } catch (error) {
      console.error('Error unlinking Google account:', error);
      throw error;
    }
  }

  static async verifyPassword(password, hashedPassword) {
    if (!hashedPassword) {
      return false; // Google-only users don't have passwords
    }
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
      .select('id, email, full_name, profile_picture');

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
      .select('id, email, full_name, profile_picture');

    if (error) {
      throw error;
    }

    return data[0];
  }

  static async updateLastLogin(userId) {
    try {
      await supabase
        .from('profiles')
        .update({ 
          last_login: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', userId);
    } catch (error) {
      console.error('Error updating last login:', error);
      // Don't throw here, as this is not critical
    }
  }

  static async updateProfile(userId, updateData) {
    try {
      const allowedFields = ['full_name', 'profile_picture', 'phone', 'bio'];
      const updates = {};
      
      // Only include allowed fields
      Object.keys(updateData).forEach(key => {
        if (allowedFields.includes(key) && updateData[key] !== undefined) {
          updates[key] = updateData[key];
        }
      });

      if (Object.keys(updates).length === 0) {
        throw new Error('No valid fields to update');
      }

      updates.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('profiles')
        .update(updates)
        .eq('id', userId)
        .select('id, email, full_name, profile_picture, phone, bio, auth_provider, updated_at');

      if (error) {
        throw error;
      }

      return data[0];
    } catch (error) {
      console.error('Error updating profile:', error);
      throw error;
    }
  }

  static async deleteUser(userId) {
    try {
      const { error } = await supabase
        .from('profiles')
        .delete()
        .eq('id', userId);

      if (error) {
        throw error;
      }

      return true;
    } catch (error) {
      console.error('Error deleting user:', error);
      throw error;
    }
  }

  static async findByGoogleId(googleId) {
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
      return null;
    }
  }

  static async getUserStats(userId) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('id, email, full_name, profile_picture, auth_provider, created_at, last_login, updated_at')
        .eq('id', userId)
        .single();

      if (error) {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error getting user stats:', error);
      throw error;
    }
  }

  static async listUsers(limit = 50, offset = 0) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('id, email, full_name, profile_picture, auth_provider, created_at, last_login')
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) {
        throw error;
      }

      return data;
    } catch (error) {
      console.error('Error listing users:', error);
      throw error;
    }
  }

  // Helper method to check if user can authenticate with password
  static async canAuthenticateWithPassword(userId) {
    try {
      const user = await this.findById(userId);
      return !!(user && user.password_hash);
    } catch (error) {
      console.error('Error checking password authentication:', error);
      return false;
    }
  }

  // Helper method to check if user can authenticate with Google
  static async canAuthenticateWithGoogle(userId) {
    try {
      const user = await this.findById(userId);
      return !!(user && user.google_id);
    } catch (error) {
      console.error('Error checking Google authentication:', error);
      return false;
    }
  }
}

module.exports = UserService;