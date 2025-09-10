const express = require('express');
const Joi = require('joi');
const { getCDRModel } = require('../models/CDR');
const { auth, checkPermission } = require('../middleware/auth');

const router = express.Router();

// Validation schemas
const querySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(1000).default(50),
  sortBy: Joi.string().valid('startTime', 'duration', 'cost', 'fromNumber', 'toNumber', 'historyId', 'durationSeconds').default('startTime'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  search: Joi.string().allow('').optional(),
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().optional(),
  callType: Joi.string().valid('incoming', 'outgoing', 'internal').optional(),
  status: Joi.string().valid('answered', 'unanswered', 'redirected', 'waiting').optional(),
  terminationReason: Joi.string().optional(),
  areaCode: Joi.string().optional(),
  trunkNumber: Joi.string().optional(),
  collection: Joi.string().valid('cdrs_143.198.0.104', 'cdrs_167.71.120.52').optional()
});

// @route   GET /api/cdr/call-logs
// @desc    Get call logs with filtering and pagination
// @access  Private
router.get('/call-logs', auth, checkPermission('viewCallLogs'), async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = querySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const {
      page,
      limit,
      sortBy,
      sortOrder,
      search,
      dateFrom,
      dateTo,
      callType,
      status,
      terminationReason,
      areaCode,
      trunkNumber,
      collection
    } = value;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build query using actual database field names
    const query = {};

    // Date range filter
    if (dateFrom || dateTo) {
      query['time-start'] = {};
      if (dateFrom) query['time-start'].$gte = new Date(dateFrom);
      if (dateTo) query['time-start'].$lte = new Date(dateTo);
    }

    // Filter by call type - we'll filter after transformation since it's derived from fromNumber
    let callTypeFilter = null;
    if (callType) {
      callTypeFilter = callType;
    }

    // Filter by status - we'll need to filter after transformation since it's derived
    // For now, we'll skip this filter at the database level

    // Filter by termination reason
    if (terminationReason) query['reason-terminated'] = terminationReason;

    // Filter by area code - we'll filter after transformation since it's extracted
    // For now, we'll skip this filter at the database level

    // Filter by trunk number
    if (trunkNumber) query['dial-no'] = trunkNumber;

    // Search functionality using actual database field names
    if (search) {
      query.$or = [
        { historyid: { $regex: search, $options: 'i' } },
        { 'from-no': { $regex: search, $options: 'i' } },
        { 'to-no': { $regex: search, $options: 'i' } },
        { 'reason-terminated': { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate skip value for pagination
    const skip = (page - 1) * limit;

    // Build sort object using actual database field names
    const sort = {};
    const sortFieldMap = {
      'startTime': 'time-start',
      'duration': 'duration',
      'cost': 'bill-cost',
      'fromNumber': 'from-no',
      'toNumber': 'to-no',
      'historyId': 'historyid',
      'durationSeconds': 'duration' // We'll sort by duration string for now
    };
    const actualSortField = sortFieldMap[sortBy] || 'time-start';
    sort[actualSortField] = sortOrder === 'asc' ? 1 : -1;

    // Execute query with pagination
    const [rawCallLogs, totalCount] = await Promise.all([
      CDR.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      CDR.countDocuments(query)
    ]);

    // Transform raw data to expected frontend format
    const callLogs = rawCallLogs.map(log => {
      const fromNumber = log['from-no'] || log.fromNumber || '';
      const toNumber = log['to-no'] || log.toNumber || '';
      const callType = determineCallType(log['from-type'], log['to-type'], fromNumber);
      
      return {
        _id: log._id,
        historyId: log.historyid || log.historyId || '',
        startTime: log['time-start'] || log.startTime || '',
        endTime: log['time-end'] || log.endTime || '',
        duration: log.duration || '',
        durationSeconds: calculateDurationSeconds(log.duration, log['time-start'], log['time-end']),
        fromNumber,
        toNumber,
        terminationReason: log['reason-terminated'] || log.terminationReason || '',
        cost: parseFloat(log['bill-cost'] || log.cost || 0),
        callType,
        trunkNumber: log['dial-no'] || log.trunkNumber || '',
        // STATE: Only for outgoing calls, first 2 digits of TO number
        stateCode: callType === 'outgoing' ? extractStateCode(toNumber) : '',
        // AREA CODE: Only for outgoing calls, digits 3-5 of TO number (after state)
        areaCode: callType === 'outgoing' ? extractAreaCode(toNumber) : '',
        extension: log['from-dn'] || log.extension || '',
        status: determineCallStatus(log['time-answered'], log['reason-terminated'])
      };
    });

    // Filter by call type after transformation (since it's derived from fromNumber)
    let filteredCallLogs = callLogs;
    if (callTypeFilter) {
      filteredCallLogs = callLogs.filter(log => log.callType === callTypeFilter);
    }

    // Recalculate pagination for filtered results
    const filteredTotalCount = filteredCallLogs.length;
    const filteredTotalPages = Math.ceil(filteredTotalCount / limit);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedFilteredLogs = filteredCallLogs.slice(startIndex, endIndex);

    // Helper function to calculate duration in seconds
    function calculateDurationSeconds(duration, startTime, endTime) {
      if (duration && duration !== '') {
        const parts = duration.split(':');
        if (parts.length === 3) {
          return parseInt(parts[0]) * 3600 + parseInt(parts[1]) * 60 + parseInt(parts[2]);
        }
      }
      if (startTime && endTime) {
        return Math.floor((new Date(endTime) - new Date(startTime)) / 1000);
      }
      return 0;
    }

    // Helper function to determine call type based on FROM field
    function determineCallType(fromType, toType, fromNumber) {
      // Business rule: If FROM starts with "Ext." it's outgoing, if FROM is a number it's incoming
      if (fromNumber && fromNumber.startsWith('Ext.')) {
        return 'outgoing';
      }
      
      // If FROM is a phone number (contains digits and doesn't start with Ext.), it's incoming
      if (fromNumber && /^\+?\d/.test(fromNumber) && !fromNumber.startsWith('Ext.')) {
        return 'incoming';
      }
      
      // Fallback to original logic for edge cases
      if (fromType === 'extension' && toType === 'external_line') return 'outgoing';
      if (fromType === 'external_line' && toType === 'extension') return 'incoming';
      if (fromType === 'extension' && toType === 'extension') return 'internal';
      
      return 'outgoing'; // default
    }

    // Helper function to determine call status
    function determineCallStatus(timeAnswered, reasonTerminated) {
      if (timeAnswered && timeAnswered !== '') return 'answered';
      if (reasonTerminated === 'src_participant_terminated') return 'unanswered';
      if (reasonTerminated === 'redirected') return 'redirected';
      return 'unanswered'; // default
    }

    // Helper function to extract state code (first 2 digits)
    function extractStateCode(phoneNumber) {
      if (!phoneNumber) return '';
      const cleaned = phoneNumber.replace(/\D/g, '');
      if (cleaned.length >= 2) {
        return cleaned.substring(0, 2);
      }
      return '';
    }

    // Helper function to extract area code (digits 3-5, after state code)
    function extractAreaCode(phoneNumber) {
      if (!phoneNumber) return '';
      const cleaned = phoneNumber.replace(/\D/g, '');
      if (cleaned.length >= 5) {
        return cleaned.substring(2, 5);
      }
      return '';
    }

    // Calculate pagination info
    const totalPages = Math.ceil(totalCount / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    res.json({
      callLogs: callTypeFilter ? paginatedFilteredLogs : callLogs,
      pagination: callTypeFilter ? {
        currentPage: page,
        totalPages: filteredTotalPages,
        totalCount: filteredTotalCount,
        limit,
        hasNextPage: page < filteredTotalPages,
        hasPrevPage: page > 1
      } : {
        currentPage: page,
        totalPages,
        totalCount,
        limit,
        hasNextPage,
        hasPrevPage
      },
      filters: {
        dateFrom,
        dateTo,
        callType,
        status,
        terminationReason,
        areaCode,
        trunkNumber,
        search
      }
    });
  } catch (error) {
    console.error('Get call logs error:', error);
    res.status(500).json({
      error: 'Server error while fetching call logs'
    });
  }
});

// @route   GET /api/cdr/area-codes
// @desc    Get area codes with call statistics
// @access  Private
router.get('/area-codes', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const { page = 1, limit = 50, sortBy = 'totalCalls', sortOrder = 'desc', collection } = req.query;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Aggregate area codes with statistics
    const pipeline = [
      {
        $match: {
          areaCode: { $exists: true, $ne: null, $ne: '' }
        }
      },
      {
        $group: {
          _id: '$areaCode',
          totalCalls: { $sum: 1 },
          answeredCalls: {
            $sum: { $cond: [{ $eq: ['$status', 'answered'] }, 1, 0] }
          },
          totalDuration: { $sum: '$durationSeconds' },
          totalCost: { $sum: '$cost' },
          avgDuration: { $avg: '$durationSeconds' }
        }
      },
      {
        $addFields: {
          areaCode: '$_id',
          answerRate: {
            $multiply: [
              { $divide: ['$answeredCalls', '$totalCalls'] },
              100
            ]
          }
        }
      },
      {
        $project: {
          _id: 0,
          areaCode: 1,
          totalCalls: 1,
          answeredCalls: 1,
          totalDuration: 1,
          totalCost: { $round: ['$totalCost', 2] },
          avgDuration: { $round: ['$avgDuration', 0] },
          answerRate: { $round: ['$answerRate', 2] }
        }
      }
    ];

    // Add sorting
    const sortObj = {};
    sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;
    pipeline.push({ $sort: sortObj });

    // Execute aggregation
    const areaCodes = await CDR.aggregate(pipeline);

    // Calculate total calls for percentage calculation
    const totalCallsAcrossAllAreas = areaCodes.reduce((sum, area) => sum + area.totalCalls, 0);

    // Add percentage to each area code
    const areaCodesWithPercentage = areaCodes.map(area => ({
      ...area,
      percentage: totalCallsAcrossAllAreas > 0 
        ? Math.round((area.totalCalls / totalCallsAcrossAllAreas) * 10000) / 100
        : 0
    }));

    // Apply pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const paginatedResults = areaCodesWithPercentage.slice(skip, skip + parseInt(limit));

    res.json({
      areaCodes: paginatedResults,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(areaCodesWithPercentage.length / parseInt(limit)),
        totalCount: areaCodesWithPercentage.length,
        limit: parseInt(limit)
      },
      summary: {
        totalAreaCodes: areaCodesWithPercentage.length,
        totalCalls: totalCallsAcrossAllAreas
      }
    });
  } catch (error) {
    console.error('Get area codes error:', error);
    res.status(500).json({
      error: 'Server error while fetching area codes'
    });
  }
});

// @route   GET /api/cdr/extensions
// @desc    Get extensions with call statistics
// @access  Private
router.get('/extensions', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const { page = 1, limit = 50, collection } = req.query;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Aggregate extensions with statistics
    const pipeline = [
      {
        $match: {
          extension: { $exists: true, $ne: null, $ne: '' }
        }
      },
      {
        $group: {
          _id: '$extension',
          totalCalls: { $sum: 1 },
          incomingCalls: {
            $sum: { $cond: [{ $eq: ['$callType', 'incoming'] }, 1, 0] }
          },
          outgoingCalls: {
            $sum: { $cond: [{ $eq: ['$callType', 'outgoing'] }, 1, 0] }
          },
          totalDuration: { $sum: '$durationSeconds' },
          totalCost: { $sum: '$cost' }
        }
      },
      {
        $addFields: {
          extension: '$_id',
          avgDuration: { $divide: ['$totalDuration', '$totalCalls'] }
        }
      },
      {
        $project: {
          _id: 0,
          extension: 1,
          totalCalls: 1,
          incomingCalls: 1,
          outgoingCalls: 1,
          totalDuration: 1,
          totalCost: { $round: ['$totalCost', 2] },
          avgDuration: { $round: ['$avgDuration', 0] }
        }
      },
      { $sort: { totalCalls: -1 } }
    ];

    const extensions = await CDR.aggregate(pipeline);

    // Apply pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const paginatedResults = extensions.slice(skip, skip + parseInt(limit));

    res.json({
      extensions: paginatedResults,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(extensions.length / parseInt(limit)),
        totalCount: extensions.length,
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Get extensions error:', error);
    res.status(500).json({
      error: 'Server error while fetching extensions'
    });
  }
});

// @route   GET /api/cdr/call-logs/:id
// @desc    Get specific call log by ID
// @access  Private
router.get('/call-logs/:id', auth, checkPermission('viewCallLogs'), async (req, res) => {
  try {
    const { collection } = req.query;
    
    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);
    
    const callLog = await CDR.findById(req.params.id);
    
    if (!callLog) {
      return res.status(404).json({
        error: 'Call log not found'
      });
    }

    res.json({ callLog });
  } catch (error) {
    console.error('Get call log error:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        error: 'Invalid call log ID format'
      });
    }

    res.status(500).json({
      error: 'Server error while fetching call log'
    });
  }
});

// @route   GET /api/cdr/area-codes
// @desc    Get area codes with call statistics  
// @access  Private
router.get('/area-codes', auth, checkPermission('viewCallLogs'), async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = querySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Invalid query parameters',
        details: error.details[0].message
      });
    }

    const {
      page,
      limit,
      sortBy = 'totalCalls',
      sortOrder = 'desc',
      search = '',
      dateFrom,
      dateTo,
      collection = process.env.MONGODB_COLLECTION1
    } = value;

    console.log(`🚀 Processing area codes for collection: ${collection}`);

    // Get the appropriate CDR model
    const CDR = getCDRModel(collection);

    // First, let's see what kind of data we have
    const sampleRecords = await CDR.find({}).limit(5).lean();
    console.log('📋 Sample CDR records:', JSON.stringify(sampleRecords.map(r => ({
      callType: r.callType,
      fromNumber: r.fromNumber,
      toNumber: r.toNumber,
      areaCode: r.areaCode,
      status: r.status
    })), null, 2));

    // Count total outgoing calls
    const outgoingCount = await CDR.countDocuments({ callType: 'outgoing' });
    console.log(`📞 Total outgoing calls: ${outgoingCount}`);

    // Build match conditions for OUTGOING calls only
    const matchConditions = {
      callType: 'outgoing'
    };

    // Date filtering
    if (dateFrom || dateTo) {
      matchConditions.startTime = {};
      if (dateFrom) matchConditions.startTime.$gte = new Date(dateFrom);
      if (dateTo) matchConditions.startTime.$lte = new Date(dateTo);
    }

    console.log('🔍 Match conditions:', JSON.stringify(matchConditions, null, 2));

    // Simplified aggregation pipeline
    const pipeline = [
      { $match: matchConditions },
      {
        $addFields: {
          // Extract area code from destination number (toNumber for outgoing calls)
          extractedAreaCode: {
            $let: {
              vars: {
                // Clean the phone number (remove +1, spaces, dashes, etc.)
                cleanNumber: {
                  $regexReplace: {
                    input: { $toString: "$toNumber" },
                    regex: /[\+\-\s\(\)]/g,
                    replacement: ""
                  }
                }
              },
              in: {
                $cond: {
                  if: { $gte: [{ $strLenCP: "$$cleanNumber" }, 10] },
                  then: {
                    $cond: {
                      if: { $eq: [{ $substr: ["$$cleanNumber", 0, 1] }, "1"] },
                      // If starts with 1, take next 3 digits (US/Canada format)
                      then: { $substr: ["$$cleanNumber", 1, 3] },
                      // Otherwise take first 3 digits
                      else: { $substr: ["$$cleanNumber", 0, 3] }
                    }
                  },
                  else: {
                    // Fallback to existing areaCode field
                    $ifNull: ["$areaCode", null]
                  }
                }
              }
            }
          }
        }
      },
      {
        $match: {
          extractedAreaCode: { $ne: null, $exists: true, $ne: "" }
        }
      },
      {
        $group: {
          _id: "$extractedAreaCode",
          totalCalls: { $sum: 1 },
          answeredCalls: {
            $sum: {
              $cond: [
                { $in: ["$status", ["answered", "completed"]] },
                1, 0
              ]
            }
          },
          totalDuration: { $sum: { $ifNull: ["$durationSeconds", 0] } },
          totalCost: { $sum: { $toDouble: { $ifNull: ["$cost", 0] } } }
        }
      },
      {
        $addFields: {
          areaCode: "$_id",
          answerRate: {
            $cond: {
              if: { $gt: ["$totalCalls", 0] },
              then: {
                $multiply: [
                  { $divide: ["$answeredCalls", "$totalCalls"] },
                  100
                ]
              },
              else: 0
            }
          },
          avgDuration: {
            $cond: {
              if: { $gt: ["$answeredCalls", 0] },
              then: { $divide: ["$totalDuration", "$answeredCalls"] },
              else: 0
            }
          },
          // Enhanced state mapping for North American area codes
          state: {
            $switch: {
              branches: [
                // California
                { case: { $in: ["$_id", ["213", "323", "424", "661", "747", "818", "310", "562", "626", "714", "760", "805", "831", "858", "909", "916", "925", "949", "951"]] }, then: "California" },
                // New York 
                { case: { $in: ["$_id", ["212", "646", "917", "718", "347", "929", "516", "631", "845", "914"]] }, then: "New York" },
                // Florida
                { case: { $in: ["$_id", ["305", "786", "954", "561", "407", "321", "727", "813", "850", "863", "904", "941", "239"]] }, then: "Florida" },
                // Texas
                { case: { $in: ["$_id", ["214", "469", "972", "945", "713", "281", "832", "409", "430", "903", "940", "979"]] }, then: "Texas" },
                // Illinois
                { case: { $in: ["$_id", ["312", "773", "872", "630", "708", "847", "224"]] }, then: "Illinois" },
                // Special case for your example: 92
                { case: { $eq: ["$_id", "92"] }, then: "California" }
              ],
              default: "Unknown"
            }
          }
        }
      },
      { $project: { _id: 0 } }
    ];

    // Search filtering (after grouping)
    if (search) {
      pipeline.push({
        $match: {
          $or: [
            { areaCode: { $regex: search, $options: 'i' } },
            { state: { $regex: search, $options: 'i' } }
          ]
        }
      });
    }

    // Add sorting
    pipeline.push({ $sort: { [sortBy]: sortOrder === 'desc' ? -1 : 1 } });

    // Get total count for pagination
    const countPipeline = [...pipeline];
    // Remove sorting and pagination stages for counting
    const pipelineForCount = pipeline.filter(stage => 
      !stage.$sort && !stage.$skip && !stage.$limit
    );
    pipelineForCount.push({ $count: 'total' });
    
    const countResult = await CDR.aggregate(pipelineForCount);
    const totalCount = countResult.length > 0 ? countResult[0].total : 0;

    // Add pagination to main pipeline
    pipeline.push({ $skip: (page - 1) * limit });
    pipeline.push({ $limit: limit });

    // Execute aggregation
    const startTime = Date.now();
    
    console.log('🔍 Area codes aggregation pipeline:', JSON.stringify(pipeline.slice(0, 3), null, 2));
    
    const areaCodes = await CDR.aggregate(pipeline);
    const endTime = Date.now();

    // Calculate pagination info
    const totalPages = Math.ceil(totalCount / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    console.log(`✨ Area codes aggregation completed in ${endTime - startTime}ms`);
    console.log(`📊 Found ${areaCodes.length} area codes from ${totalCount} total records`);
    console.log('🎯 Sample area codes:', areaCodes.slice(0, 3));

    res.json({
      success: true,
      areaCodes,
      pagination: {
        currentPage: page,
        totalPages,
        totalCount,
        limit,
        hasNextPage,
        hasPrevPage
      }
    });

  } catch (error) {
    console.error('Get area codes error:', error);
    res.status(500).json({
      error: 'Server error while fetching area codes',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;