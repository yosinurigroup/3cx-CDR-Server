const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
    index: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email'],
    index: true
  },
  password: {
    type: String,
    required: function() {
      // Password is required only if googleId is not present
      return !this.googleId;
    },
    minlength: 6
  },
  googleId: {
    type: String,
    sparse: true, // Allows null values but ensures uniqueness when present
    index: true
  },
  avatar: {
    type: String,
    default: null
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  role: {
    type: String,
    enum: ['admin', 'manager', 'user', 'viewer'],
    default: 'user',
    index: true
  },
  department: {
    type: String,
    trim: true,
    maxlength: 100
  },
  extension: {
    type: String,
    trim: true,
    maxlength: 10,
    index: true
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'system'],
      default: 'system'
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    dateFormat: {
      type: String,
      enum: ['MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD'],
      default: 'MM/DD/YYYY'
    },
    itemsPerPage: {
      type: Number,
      default: 50,
      min: 10,
      max: 100
    }
  },
  permissions: {
    viewAnalytics: {
      type: Boolean,
      default: true
    },
    viewCallLogs: {
      type: Boolean,
      default: true
    },
    exportData: {
      type: Boolean,
      default: false
    },
    manageUsers: {
      type: Boolean,
      default: false
    },
    systemSettings: {
      type: Boolean,
      default: false
    }
  },
  databasePermissions: [{
    type: String,
    enum: ['cdrs_143.198.0.104', 'cdrs_167.71.120.52']
  }]
}, {
  timestamps: true,
  collection: process.env.MONGODB_USERS_COLLECTION || 'tblUsers'
});

// Indexes
userSchema.index({ username: 1, email: 1 });
userSchema.index({ role: 1, isActive: 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Skip password hashing for Google OAuth users
  if (this.googleId && !this.password) {
    return next();
  }
  
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw error;
  }
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 },
    $set: { lastLogin: new Date() }
  });
};

// Static method to find user by username or email
userSchema.statics.findByLogin = function(login) {
  return this.findOne({
    $or: [
      { username: login },
      { email: login }
    ],
    isActive: true
  });
};

// Static method to find or create user by Google profile
userSchema.statics.findOrCreateByGoogle = async function(googleProfile) {
  try {
    // First check if user exists by Google ID
    let user = await this.findOne({ googleId: googleProfile.sub });
    
    if (user) {
      // Update avatar if changed
      if (user.avatar !== googleProfile.picture) {
        user.avatar = googleProfile.picture;
        await user.save();
      }
      return user;
    }

    // Check if user exists by email
    user = await this.findOne({ email: googleProfile.email });
    
    if (user) {
      // Link Google account to existing user
      user.googleId = googleProfile.sub;
      user.avatar = googleProfile.picture || user.avatar;
      await user.save();
      return user;
    }

    // Create new user
    const newUser = new this({
      googleId: googleProfile.sub,
      email: googleProfile.email,
      username: googleProfile.email.split('@')[0], // Use email prefix as username
      firstName: googleProfile.given_name || 'User',
      lastName: googleProfile.family_name || '',
      avatar: googleProfile.picture,
      role: 'user',
      databasePermissions: [] // No database permissions by default
    });

    return await newUser.save();
  } catch (error) {
    throw error;
  }
};

// Method to get user permissions based on role
userSchema.methods.getEffectivePermissions = function() {
  const rolePermissions = {
    admin: {
      viewAnalytics: true,
      viewCallLogs: true,
      exportData: true,
      manageUsers: true,
      systemSettings: true
    },
    manager: {
      viewAnalytics: true,
      viewCallLogs: true,
      exportData: true,
      manageUsers: false,
      systemSettings: false
    },
    user: {
      viewAnalytics: true,
      viewCallLogs: true,
      exportData: false,
      manageUsers: false,
      systemSettings: false
    },
    viewer: {
      viewAnalytics: true,
      viewCallLogs: false,
      exportData: false,
      manageUsers: false,
      systemSettings: false
    }
  };

  // Merge role permissions with user-specific permissions
  return {
    ...rolePermissions[this.role],
    ...this.permissions
  };
};

// Transform output to remove sensitive data
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.loginAttempts;
  delete user.lockUntil;
  return user;
};

module.exports = mongoose.model('User', userSchema);