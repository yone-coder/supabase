{
  "name": "express-auth-server",
  "version": "1.0.0",
  "description": "Express.js server with authentication for Render.com",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [
    "express",
    "authentication",
    "jwt",
    "supabase",
    "render",
    "otp",
    "email",
    "resend"
  ],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "@supabase/supabase-js": "^2.39.3",
    "bcrypt": "^5.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "resend": "^4.6.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}