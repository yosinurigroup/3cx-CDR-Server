const express = require('express');
const Joi = require('joi');
const User = require('../models/User');
const { auth, checkPermission, checkRole } = require('../middleware/auth');

const router = express.Router();

// Validation schemas
const createUserSchema = Joi.object({
  username: Joi.string().min(3).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).max(128).required(),
  firstName: Joi.string().max(50).required(),
  lastName: Joi.string().max(50).required(),
  department: Joi.string().max(100).optional(),
  extension: Joi.string().max(10).optional(),
  role: Joi.string().valid('admin', 'manager', 'user', 'viewer').default('user'),
  databasePermissions: Joi.array().items(Joi.string()).optional(),
  permissions: Joi.object({
    viewAnalytics: Joi.boolean().optional(),
    viewCallLogs: Joi.boolean().optional(),
    exportData: Joi.boolean().optional(),
    manageUsers: Joi.boolean().optional(),
    systemSettings: Joi.boolean().optional()
  }).optional(),
  preferences: Joi.object({
    theme: Joi.string().valid('light', 'dark', 'system').default('system'),
    timezone: Joi.string().default('UTC'),
    dateFormat: Joi.string().valid('MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD').default('MM/DD/YYYY'),
    itemsPerPage: Joi.number().min(10).max(100).default(20)
  }).optional()
});

const updateUserSchema = Joi.object({
  firstName: Joi.string().max(50).optional(),
  lastName: Joi.string().max(50).optional(),
  email: Joi.string().email().optional(),
  department: Joi.string().max(100).optional(),
  extension: Joi.string().max(10).optional(),
  role: Joi.string().valid('admin', 'manager', 'user', 'viewer').optional(),
  isActive: Joi.boolean().optional(),
  databasePermissions: Joi.array().items(Joi.string()).optional(),
  permissions: Joi.object({
    viewAnalytics: Joi.boolean().optional(),
    viewCallLogs: Joi.boolean().optional(),
    exportData: Joi.boolean().optional(),
    manageUsers: Joi.boolean().optional(),
    systemSettings: Joi.boolean().optional()
  }).optional(),
  preferences: Joi.object({
    theme: Joi.string().valid('light', 'dark', 'system').optional(),
    timezone: Joi.string().optional(),
    dateFormat: Joi.string().valid('MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD').optional(),
    itemsPerPage: Joi.number().min(10).max(100).optional()
  }).optional()
});

const querySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  search: Joi.string().optional(),
  role: Joi.string().valid('admin', 'manager', 'user', 'viewer').optional(),
  isActive: Joi.boolean().optional(),
  sortBy: Joi.string().valid('username', 'email', 'firstName', 'lastName', 'role', 'createdAt').default('createdAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

// @route   GET /api/users
// @desc    Get all users with filtering and pagination
// @access  Private (Admin/Manager)
router.get('/', auth, checkRole(['admin', 'manager']), async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = querySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { page, limit, search, role, isActive, sortBy, sortOrder } = value;

    // Build query
    const query = {};

    // Search functionality
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { department: { $regex: search, $options: 'i' } }
      ];
    }

    // Filter by role
    if (role) query.role = role;

    // Filter by active status
    if (typeof isActive === 'boolean') query.isActive = isActive;

    // Calculate skip value for pagination
    const skip = (page - 1) * limit;

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Execute query with pagination
    const [users, totalCount] = await Promise.all([
      User.find(query)
        .select('-password -loginAttempts -lockUntil')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(query)
    ]);

    // Calculate pagination info
    const totalPages = Math.ceil(totalCount / limit);

    res.json({
      users,
      pagination: {
        currentPage: page,
        totalPages,
        totalCount,
        limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      error: 'Server error while fetching users'
    });
  }
});

// @route   POST /api/users
// @desc    Create new user
// @access  Private (Admin only)
router.post('/', auth, checkRole('admin'), async (req, res) => {
  try {
    // Validate input
    const { error, value } = createUserSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const {
      username,
      email,
      password,
      firstName,
      lastName,
      department,
      extension,
      role,
      databasePermissions,
      permissions,
      preferences
    } = value;

    // Check if username or email already exists
    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(400).json({
        error: existingUser.username === username 
          ? 'Username already exists' 
          : 'Email already exists'
      });
    }

    // Set default permissions based on role
    const defaultPermissions = {
      viewAnalytics: true,
      viewCallLogs: role !== 'viewer',
      exportData: ['admin', 'manager'].includes(role),
      manageUsers: role === 'admin',
      systemSettings: role === 'admin'
    };

    // Create new user
    const newUser = new User({
      username,
      email,
      password, // Will be hashed by the User model's pre-save middleware
      firstName,
      lastName,
      fullName: `${firstName} ${lastName}`,
      department,
      extension,
      role,
      databasePermissions: databasePermissions || [],
      permissions: { ...defaultPermissions, ...permissions },
      preferences: {
        theme: 'system',
        timezone: 'UTC',
        dateFormat: 'MM/DD/YYYY',
        itemsPerPage: 20,
        ...preferences
      },
      isActive: true
    });

    await newUser.save();

    // Remove password from response
    const userResponse = newUser.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;

    res.status(201).json({
      message: 'User created successfully',
      user: {
        ...userResponse,
        effectivePermissions: newUser.getEffectivePermissions()
      }
    });
  } catch (error) {
    console.error('Create user error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        error: 'Username or email already exists'
      });
    }

    res.status(500).json({
      error: 'Server error while creating user'
    });
  }
});

// @route   GET /api/users/:id
// @desc    Get user by ID
// @access  Private (Admin/Manager or own profile)
router.get('/:id', auth, async (req, res) => {
  try {
    const requestedUserId = req.params.id;
    const currentUserId = req.user.userId;
    const currentUserRole = req.user.role;

    // Check if user can access this profile
    const canAccess =
      req.user.isSuperAdmin ||
      requestedUserId === currentUserId.toString() ||
      ['admin', 'manager'].includes(currentUserRole);

    if (!canAccess) {
      return res.status(403).json({
        error: 'Access denied. You can only view your own profile.'
      });
    }

    const user = await User.findById(requestedUserId)
      .select('-password -loginAttempts -lockUntil');

    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      user: {
        ...user.toObject(),
        effectivePermissions: user.getEffectivePermissions()
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        error: 'Invalid user ID format'
      });
    }

    res.status(500).json({
      error: 'Server error while fetching user'
    });
  }
});

// @route   PUT /api/users/:id
// @desc    Update user
// @access  Private (Admin or own profile with restrictions)
router.put('/:id', auth, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const currentUserId = req.user.userId;
    const currentUserRole = req.user.role;

    // Validate input
    const { error, value } = updateUserSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    // Check permissions
    const isOwnProfile = targetUserId === currentUserId.toString();
    const isAdmin = currentUserRole === 'admin' || req.user.isSuperAdmin;

    if (!isOwnProfile && !isAdmin) {
      return res.status(403).json({
        error: 'Access denied. You can only update your own profile.'
      });
    }

    // Restrict certain fields for non-admin users
    if (!isAdmin && isOwnProfile) {
      delete value.role;
      delete value.isActive;
      delete value.permissions;
    }

    // Find and update user
    const user = await User.findById(targetUserId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // Check for email uniqueness if email is being updated
    if (value.email && value.email !== user.email) {
      const existingUser = await User.findOne({ email: value.email });
      if (existingUser) {
        return res.status(400).json({
          error: 'Email already exists'
        });
      }
    }

    // Update user fields
    Object.keys(value).forEach(key => {
      if (key === 'permissions' && value[key]) {
        user.permissions = { ...user.permissions, ...value[key] };
      } else if (key === 'preferences' && value[key]) {
        user.preferences = { ...user.preferences, ...value[key] };
      } else {
        user[key] = value[key];
      }
    });

    await user.save();

    res.json({
      message: 'User updated successfully',
      user: {
        ...user.toObject(),
        effectivePermissions: user.getEffectivePermissions()
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        error: 'Invalid user ID format'
      });
    }

    res.status(500).json({
      error: 'Server error while updating user'
    });
  }
});

// @route   DELETE /api/users/:id
// @desc    Delete user (soft delete by setting isActive to false)
// @access  Private (Admin only)
router.delete('/:id', auth, checkRole('admin'), async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const currentUserId = req.user.userId;

    // Prevent admin from deleting themselves
    if (targetUserId === currentUserId.toString()) {
      return res.status(400).json({
        error: 'You cannot delete your own account'
      });
    }

    // Prevent deletion of super admin (if someone tries to delete the static ID)
    if (targetUserId === 'super-admin-static') {
      return res.status(400).json({
        error: 'Super admin account cannot be deleted'
      });
    }

    const user = await User.findById(targetUserId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // Soft delete by setting isActive to false
    user.isActive = false;
    await user.save();

    res.json({
      message: 'User deactivated successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        error: 'Invalid user ID format'
      });
    }

    res.status(500).json({
      error: 'Server error while deleting user'
    });
  }
});

// @route   PUT /api/users/:id/activate
// @desc    Reactivate user
// @access  Private (Admin only)
router.put('/:id/activate', auth, checkRole('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    user.isActive = true;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    res.json({
      message: 'User activated successfully',
      user: user.toObject()
    });
  } catch (error) {
    console.error('Activate user error:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        error: 'Invalid user ID format'
      });
    }

    res.status(500).json({
      error: 'Server error while activating user'
    });
  }
});

// @route   GET /api/users/stats/summary
// @desc    Get user statistics summary
// @access  Private (Admin/Manager)
router.get('/stats/summary', auth, checkRole(['admin', 'manager']), async (req, res) => {
  try {
    const [
      totalUsers,
      activeUsers,
      adminUsers,
      managerUsers,
      regularUsers,
      viewerUsers,
      recentUsers
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true }),
      User.countDocuments({ role: 'admin', isActive: true }),
      User.countDocuments({ role: 'manager', isActive: true }),
      User.countDocuments({ role: 'user', isActive: true }),
      User.countDocuments({ role: 'viewer', isActive: true }),
      User.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
      })
    ]);

    res.json({
      summary: {
        totalUsers,
        activeUsers,
        inactiveUsers: totalUsers - activeUsers,
        recentUsers,
        roleDistribution: {
          admin: adminUsers,
          manager: managerUsers,
          user: regularUsers,
          viewer: viewerUsers
        }
      }
    });
  } catch (error) {
    console.error('User stats error:', error);
    res.status(500).json({
      error: 'Server error while fetching user statistics'
    });
  }
});

module.exports = router;