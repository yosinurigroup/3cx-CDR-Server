const express = require('express');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Initialize Google OAuth2 client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Validation schemas
const loginSchema = Joi.object({
  login: Joi.string().required().min(3).max(100),
  password: Joi.string().required().min(6)
});

const googleAuthSchema = Joi.object({
  credential: Joi.string().required()
});

const registerSchema = Joi.object({
  username: Joi.string().required().min(3).max(50).alphanum(),
  email: Joi.string().required().email(),
  password: Joi.string().required().min(6),
  firstName: Joi.string().required().max(50),
  lastName: Joi.string().required().max(50),
  department: Joi.string().optional().max(100),
  extension: Joi.string().optional().max(10)
});

const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().required().min(6)
});

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', async (req, res) => {
  try {
    // Validate input
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { login, password } = req.body;

    // Find user by username or email in users table only
    const user = await User.findByLogin(login);
    if (!user) {
      return res.status(401).json({
        error: 'Invalid credentials'
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      return res.status(423).json({
        error: 'Account temporarily locked due to too many failed login attempts'
      });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await user.incLoginAttempts();
      return res.status(401).json({
        error: 'Invalid credentials'
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Generate token
    const token = generateToken(user._id);

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        role: user.role,
        department: user.department,
        extension: user.extension,
        permissions: user.getEffectivePermissions(),
        preferences: user.preferences,
        databasePermissions: user.databasePermissions
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Server error during login'
    });
  }
});

// @route   POST /api/auth/google
// @desc    Google OAuth login/signup
// @access  Public
router.post('/google', async (req, res) => {
  try {
    // Validate input
    const { error } = googleAuthSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { credential } = req.body;

    // Verify Google token
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, given_name, family_name, name, picture } = payload;

    if (!email) {
      return res.status(400).json({
        error: 'Email not provided by Google'
      });
    }

    // Check if user already exists
    let user = await User.findOne({ email });

    if (user) {
      // User exists, log them in
      await user.resetLoginAttempts(); // Update last login

      const token = generateToken(user._id);

      return res.json({
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName,
          role: user.role,
          department: user.department,
          extension: user.extension,
          permissions: user.getEffectivePermissions(),
          preferences: user.preferences,
          databasePermissions: user.databasePermissions
        },
        isNewUser: false
      });
    } else {
      // Create new user with Google info
      const firstName = given_name || name?.split(' ')[0] || 'Google';
      const lastName = family_name || name?.split(' ').slice(1).join(' ') || 'User';
      const username = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
      
      // Generate a random password for Google users
      const randomPassword = Math.random().toString(36).slice(-12) + 'A1!';

      // Create new user
      user = new User({
        username: `${username}_${Date.now()}`, // Ensure uniqueness
        email,
        password: randomPassword,
        firstName,
        lastName,
        role: 'user', // Default role
        databasePermissions: [], // No database permissions by default
        isActive: true,
        googleId: payload.sub,
        avatar: picture,
        preferences: {
          theme: 'system',
          timezone: 'UTC',
          dateFormat: 'MM/DD/YYYY',
          itemsPerPage: 20
        }
      });

      await user.save();

      const token = generateToken(user._id);

      return res.json({
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName,
          role: user.role,
          department: user.department,
          extension: user.extension,
          permissions: user.getEffectivePermissions(),
          preferences: user.preferences,
          databasePermissions: user.databasePermissions
        },
        isNewUser: true
      });
    }
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({
      error: 'Server error during Google authentication'
    });
  }
});

// @route   POST /api/auth/register
// @desc    Register new user (admin only)
// @access  Private (Admin)
router.post('/register', auth, async (req, res) => {
  try {
    // Check if user is admin (including super admin)
    if (req.user.isSuperAdmin) {
      // Super admin has full access
    } else {
      const currentUser = await User.findById(req.user.userId);
      if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).json({
          error: 'Access denied. Admin privileges required.'
        });
      }
    }

    // Validate input
    const { error } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { username, email, password, firstName, lastName, department, extension } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'User already exists with this username or email'
      });
    }

    // Create new user
    const user = new User({
      username,
      email,
      password,
      firstName,
      lastName,
      department,
      extension
    });

    await user.save();

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        department: user.department,
        extension: user.extension
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Server error during registration'
    });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        role: user.role,
        department: user.department,
        extension: user.extension,
        permissions: user.getEffectivePermissions(),
        preferences: user.preferences,
        databasePermissions: user.databasePermissions,
        lastLogin: user.lastLogin,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      error: 'Server error'
    });
  }
});

// @route   PUT /api/auth/change-password
// @desc    Change user password
// @access  Private
router.put('/change-password', auth, async (req, res) => {
  try {
    // Super admin cannot change password through this endpoint
    if (req.user.isSuperAdmin) {
      return res.status(403).json({
        error: 'Super admin password cannot be changed through this endpoint'
      });
    }

    // Validate input
    const { error } = changePasswordSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { currentPassword, newPassword } = req.body;

    // Find user
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // Verify current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    res.json({
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      error: 'Server error'
    });
  }
});

// @route   POST /api/auth/logout
// @desc    Logout user (client-side token removal)
// @access  Private
router.post('/logout', auth, (req, res) => {
  res.json({
    message: 'Logged out successfully'
  });
});

module.exports = router;