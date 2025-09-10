const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Static Super Admin definition (matching auth.js)
const SUPER_ADMIN = {
  id: 'super-admin-static',
  username: 'superadmin',
  email: 'admin@y2kgrouphosting.com',
  role: 'admin',
  permissions: {
    viewAnalytics: true,
    viewCallLogs: true,
    exportData: true,
    manageUsers: true,
    systemSettings: true
  }
};

const auth = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.header('Authorization');
    console.log('Auth header:', authHeader ? 'Present' : 'Missing');
    const token = authHeader?.replace('Bearer ', '');

    if (!token) {
      console.log('No token found in request to:', req.path);
      return res.status(401).json({
        error: 'No token provided, authorization denied'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Handle super admin token
    if (decoded.isSuperAdmin && decoded.userId === SUPER_ADMIN.id) {
      req.user = {
        userId: SUPER_ADMIN.id,
        username: SUPER_ADMIN.username,
        role: SUPER_ADMIN.role,
        permissions: SUPER_ADMIN.permissions,
        isSuperAdmin: true
      };
      return next();
    }
    
    // Check if user still exists and is active
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({
        error: 'Token is not valid or user is inactive'
      });
    }

    // Add user to request
    req.user = {
      userId: user._id,
      username: user.username,
      role: user.role,
      permissions: user.getEffectivePermissions()
    };

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired'
      });
    }

    res.status(500).json({
      error: 'Server error in authentication'
    });
  }
};

// Middleware to check specific permissions
const checkPermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    if (!req.user.permissions[permission]) {
      return res.status(403).json({
        error: `Access denied. ${permission} permission required.`
      });
    }

    next();
  };
};

// Middleware to check specific roles
const checkRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    const userRoles = Array.isArray(roles) ? roles : [roles];
    
    if (!userRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Required role: ${userRoles.join(' or ')}`
      });
    }

    next();
  };
};

module.exports = {
  auth,
  checkPermission,
  checkRole
};