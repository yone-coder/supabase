const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const supabase = require('./database');

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const googleId = profile.id;
    const fullName = profile.displayName;
    const avatarUrl = profile.photos[0]?.value;

    // Check if user exists with this Google ID
    let { data: existingUser } = await supabase
      .from('profiles')
      .select('*')
      .eq('google_id', googleId)
      .single();

    if (existingUser) {
      // Update last login
      await supabase
        .from('profiles')
        .update({ last_login: new Date().toISOString() })
        .eq('id', existingUser.id);
      
      return done(null, existingUser);
    }

    // Check if user exists with this email (from regular signup)
    let { data: emailUser } = await supabase
      .from('profiles')
      .select('*')
      .eq('email', email)
      .single();

    if (emailUser) {
      // Link Google account to existing email account
      const { data: updatedUser } = await supabase
        .from('profiles')
        .update({
          google_id: googleId,
          auth_provider: 'google',
          avatar_url: avatarUrl,
          last_login: new Date().toISOString()
        })
        .eq('id', emailUser.id)
        .select()
        .single();

      return done(null, updatedUser);
    }

    // Create new user
    const { data: newUser, error } = await supabase
      .from('profiles')
      .insert({
        email,
        google_id: googleId,
        full_name: fullName,
        auth_provider: 'google',
        avatar_url: avatarUrl,
        last_login: new Date().toISOString()
      })
      .select()
      .single();

    if (error) {
      return done(error, null);
    }

    return done(null, newUser);
  } catch (error) {
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { data: user } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', id)
      .single();
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

module.exports = passport;