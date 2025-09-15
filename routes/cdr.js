const express = require('express');
const Joi = require('joi');
const { getCDRModel } = require('../models/CDR');
const { auth, checkPermission } = require('../middleware/auth');

const router = express.Router();

// Validation schemas
const querySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(1000).default(50),
  sortBy: Joi.string().default('startTime'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  search: Joi.string().allow('').optional(),
  dateFrom: Joi.alternatives().try(
    Joi.date(),
    Joi.string().isoDate()
  ).optional(),
  dateTo: Joi.alternatives().try(
    Joi.date(),
    Joi.string().isoDate()
  ).optional(),
  callType: Joi.string().valid('incoming', 'outgoing', 'internal').optional(),
  status: Joi.string().valid('answered', 'unanswered', 'redirected', 'waiting').optional(),
  terminationReason: Joi.string().optional(),
  extension: Joi.string().optional(),
  areaCode: Joi.string().optional(),
  trunkNumber: Joi.string().optional(),
  // Advanced filters
  stateCode: Joi.string().optional(),
  minDurationSec: Joi.number().integer().min(0).optional(),
  maxDurationSec: Joi.number().integer().min(0).optional(),
  minCost: Joi.number().min(0).optional(),
  maxCost: Joi.number().min(0).optional(),
  collection: Joi.string().valid('cdrs_143.198.0.104', 'cdrs_167.71.120.52').allow('').optional(),
  export: Joi.boolean().optional(),
  raw: Joi.boolean().optional()
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
      collection,
      extension,
      stateCode,
      minDurationSec,
      maxDurationSec,
      minCost,
      maxCost
    } = value;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build query using actual database field names
    const query = {};

    // Date range filter - handle string dates in database format "2025/09/08 15:43:15"
    if (dateFrom || dateTo) {
      query['time-start'] = {};
      if (dateFrom) {
        try {
          const fromDate = new Date(dateFrom);
          if (!isNaN(fromDate.getTime())) {
            // Convert to database string format: "YYYY/MM/DD HH:mm:ss"
            const fromStr = fromDate.getFullYear() + '/' +
                           String(fromDate.getMonth() + 1).padStart(2, '0') + '/' +
                           String(fromDate.getDate()).padStart(2, '0') + ' ' +
                           String(fromDate.getHours()).padStart(2, '0') + ':' +
                           String(fromDate.getMinutes()).padStart(2, '0') + ':' +
                           String(fromDate.getSeconds()).padStart(2, '0');
            query['time-start'].$gte = fromStr;
          }
        } catch (error) {
          console.warn('Invalid dateFrom format:', dateFrom);
        }
      }
      if (dateTo) {
        try {
          const toDate = new Date(dateTo);
          if (!isNaN(toDate.getTime())) {
            // Convert to database string format: "YYYY/MM/DD HH:mm:ss"
            const toStr = toDate.getFullYear() + '/' +
                         String(toDate.getMonth() + 1).padStart(2, '0') + '/' +
                         String(toDate.getDate()).padStart(2, '0') + ' ' +
                         String(toDate.getHours()).padStart(2, '0') + ':' +
                         String(toDate.getMinutes()).padStart(2, '0') + ':' +
                         String(toDate.getSeconds()).padStart(2, '0');
            query['time-start'].$lte = toStr;
          }
        } catch (error) {
          console.warn('Invalid dateTo format:', dateTo);
        }
      }
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

    const isExport = String(req.query.export || '').toLowerCase() === 'true';

    // TURBO MODE: Get total count first for accurate pagination
    const totalCount = await CDR.countDocuments(query);
    
    // Execute query with turbo-fast optimizations and smart pagination
    const rawCallLogs = await CDR.find(query, {
      // Only select fields we actually need for better performance
      'historyid': 1,
      'callid': 1,
      'call-id': 1,
      'time-start': 1,
      'time-end': 1,
      'duration': 1,
      'from-no': 1,
      'to-no': 1,
      'reason-terminated': 1,
      'bill-cost': 1,
      'dial-no': 1,
      'from-dn': 1,
      'from-type': 1,
      'to-type': 1,
      'final-type': 1,
      'from-dispname': 1,
      'to-dispname': 1,
      'final-dispname': 1,
      'chain': 1,
      'missed-queue-calls': 1,
      'raw_stream': 1,
      'time-answered': 1
    })
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .lean()
      .allowDiskUse(true)
      .maxTimeMS(30000);

    // Turbo-fast data transformation with optimized field access
    const callLogs = rawCallLogs.map(log => {
      const fromNumber = log['from-no'] || '';
      const toNumber = log['to-no'] || '';
      const isOutgoing = fromNumber.startsWith('Ext.');
      const callType = isOutgoing ? 'outgoing' : (/^\+?\d/.test(fromNumber) ? 'incoming' : 'outgoing');
      
      return {
        _id: log._id,
        historyId: log.historyid || '',
        callId: log['callid'] || log['call-id'] || '',
        startTime: log['time-start'] || '',
        endTime: log['time-end'] || '',
        duration: log.duration || '',
        durationSeconds: fastCalculateDuration(log.duration),
        fromNumber,
        toNumber,
        terminationReason: log['reason-terminated'] || '',
        cost: parseFloat(log['bill-cost'] || 0),
        callType,
        trunkNumber: log['dial-no'] || '',
        stateCode: isOutgoing ? fastExtractStateCode(toNumber) : '',
        areaCode: isOutgoing ? fastExtractAreaCode(toNumber) : '',
        extension: log['from-dn'] || '',
        status: log['time-answered'] ? 'answered' : 'unanswered',
        chain: log['chain'] || '',
        fromType: log['from-type'] || '',
        finalType: log['final-type'] || log['to-type'] || '',
        fromDispname: log['from-dispname'] || '',
        toDispname: log['to-dispname'] || '',
        finalDispname: log['final-dispname'] || '',
        missedQueueCalls: log['missed-queue-calls'] || 0,
        rawStream: log['raw_stream'] || ''
      };
    });

    // Optimized helper functions for speed
    function fastCalculateDuration(duration) {
      if (!duration || typeof duration !== 'string') return 0;
      const parts = duration.split(':');
      if (parts.length !== 3) return 0;
      return parseInt(parts[0]) * 3600 + parseInt(parts[1]) * 60 + parseInt(parts[2]);
    }

    function fastExtractStateCode(phoneNumber) {
      if (!phoneNumber) return '';
      const cleaned = phoneNumber.replace(/\D/g, '');
      return cleaned.length >= 2 ? cleaned.substring(0, 2) : '';
    }

    function fastExtractAreaCode(phoneNumber) {
      if (!phoneNumber) return '';
      const cleaned = phoneNumber.replace(/\D/g, '');
      return cleaned.length >= 5 ? cleaned.substring(2, 5) : '';
    }

    // Apply post-transformation filters
    let filteredCallLogs = callLogs;

    // Filter by area code (normalize to digits for robust match)
    if (areaCode) {
      const desired = String(areaCode).replace(/\D/g, '');
      filteredCallLogs = filteredCallLogs.filter(log => {
        const got = String(log.areaCode || '').replace(/\D/g, '');
        return desired ? got === desired : true;
      });
    }

    // Filter by extension (after transformation)
    if (extension) {
      const ext = String(extension).toLowerCase();
      filteredCallLogs = filteredCallLogs.filter(log =>
        (log.extension || '').toLowerCase().includes(ext)
      );
    }

    // Filter by call type after transformation (since it's derived from fromNumber)
    if (callType) {
      filteredCallLogs = filteredCallLogs.filter(log => log.callType === callType);
    }

    // State code (derived from toNumber for outgoing)
    if (stateCode) {
      filteredCallLogs = filteredCallLogs.filter(log => String(log.stateCode || '') === String(stateCode));
    }

    // Duration seconds range
    if (typeof minDurationSec === 'number') {
      filteredCallLogs = filteredCallLogs.filter(log => (log.durationSeconds || 0) >= minDurationSec);
    }
    if (typeof maxDurationSec === 'number') {
      filteredCallLogs = filteredCallLogs.filter(log => (log.durationSeconds || 0) <= maxDurationSec);
    }

    // Cost range
    if (typeof minCost === 'number') {
      filteredCallLogs = filteredCallLogs.filter(log => (Number.isFinite(log.cost) ? log.cost : 0) >= minCost);
    }
    if (typeof maxCost === 'number') {
      filteredCallLogs = filteredCallLogs.filter(log => (Number.isFinite(log.cost) ? log.cost : 0) <= maxCost);
    }

    // Apply post-transformation filters but use original pagination
    let finalLogs = callLogs;
    
    // Apply post-transformation filters
    if (areaCode) {
      const desired = String(areaCode).replace(/\D/g, '');
      finalLogs = finalLogs.filter(log => {
        const got = String(log.areaCode || '').replace(/\D/g, '');
        return desired ? got === desired : true;
      });
    }

    if (extension) {
      const ext = String(extension).toLowerCase();
      finalLogs = finalLogs.filter(log =>
        (log.extension || '').toLowerCase().includes(ext)
      );
    }

    if (callType) {
      finalLogs = finalLogs.filter(log => log.callType === callType);
    }

    if (stateCode) {
      finalLogs = finalLogs.filter(log => String(log.stateCode || '') === String(stateCode));
    }

    if (typeof minDurationSec === 'number') {
      finalLogs = finalLogs.filter(log => (log.durationSeconds || 0) >= minDurationSec);
    }
    if (typeof maxDurationSec === 'number') {
      finalLogs = finalLogs.filter(log => (log.durationSeconds || 0) <= maxDurationSec);
    }

    if (typeof minCost === 'number') {
      finalLogs = finalLogs.filter(log => (Number.isFinite(log.cost) ? log.cost : 0) >= minCost);
    }
    if (typeof maxCost === 'number') {
      finalLogs = finalLogs.filter(log => (Number.isFinite(log.cost) ? log.cost : 0) <= maxCost);
    }

    // Use database totalCount for pagination, but return filtered results
    const totalPages = Math.ceil(totalCount / limit);
    const paginatedLogs = finalLogs; // Already paginated by database query


    // CSV export handling
    if (isExport) {
      // Choose dataset honoring callType filter post-transform
      const exportRows = callType ? filteredCallLogs : callLogs;

      // Build CSV
      const headers = [
        'History ID','Start Time','End Time','Duration (s)','From','To','Type','State','Area Code','Extension','Cost','Termination Reason','Trunk','Status'
      ];
      const escapeCsv = (val) => {
        if (val === null || val === undefined) return '';
        const str = String(val);
        if (/[",\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
        return str;
      };
      const lines = [headers.join(',')];
      for (const row of exportRows) {
        lines.push([
          row.historyId,
          row.startTime ? new Date(row.startTime).toISOString() : '',
          row.endTime ? new Date(row.endTime).toISOString() : '',
          row.durationSeconds,
          row.fromNumber,
          row.toNumber,
          row.callType,
          row.stateCode || '',
          row.areaCode || '',
          row.extension || '',
          typeof row.cost === 'number' ? row.cost.toFixed(2) : '0.00',
          row.terminationReason || '',
          row.trunkNumber || '',
          row.status || ''
        ].map(escapeCsv).join(','));
      }

      const csv = lines.join('\n');
      const filename = `call-logs-${new Date().toISOString().slice(0,10)}.csv`;
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.status(200).send(csv);
    }


    res.json({
      callLogs: paginatedLogs,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalCount: totalCount,
        limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
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

// @route   GET /api/cdr/extensions
// @desc    Get extensions with call statistics
// @access  Private
router.get('/extensions', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const { page = 1, limit = 50, collection } = req.query;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Aggregate extensions with statistics (outgoing calls only)
    const pipeline = [
      {
        $addFields: {
          // Transform call type based on from-no field (same logic as dashboard)
          callType: {
            $cond: {
              if: { $regexMatch: { input: { $ifNull: ['$from-no', ''] }, regex: "^Ext\\." } },
              then: 'outgoing',
              else: 'incoming'
            }
          },
          // Extract extension from from-no field for outgoing calls
          extension: {
            $cond: {
              if: { $regexMatch: { input: { $ifNull: ['$from-no', ''] }, regex: "^Ext\\." } },
              then: { $substr: ['$from-no', 4, -1] },
              else: null
            }
          },
          // Clean cost field (same logic as dashboard)
          cost: { 
            $cond: {
              if: { 
                $and: [
                  { $ne: [{ $ifNull: ['$bill-cost', ''] }, ''] },
                  { $ne: [{ $ifNull: ['$bill-cost', ''] }, null] },
                  { $type: '$bill-cost' }
                ]
              },
              then: { 
                $convert: {
                  input: '$bill-cost',
                  to: 'double',
                  onError: 0
                }
              },
              else: 0
            }
          },
          // Clean duration field - convert string duration to seconds (same logic as dashboard)
          durationSeconds: {
            $cond: {
              if: { $and: [
                { $ne: [{ $ifNull: ['$duration', ''] }, ''] },
                { $regexMatch: { input: { $ifNull: ['$duration', ''] }, regex: "^\\d+:\\d+:\\d+$" } }
              ]},
              then: {
                $let: {
                  vars: {
                    parts: { $split: ['$duration', ':'] }
                  },
                  in: {
                    $add: [
                      { $multiply: [{
                        $convert: {
                          input: { $arrayElemAt: ['$$parts', 0] },
                          to: 'int',
                          onError: 0
                        }
                      }, 3600] },
                      { $multiply: [{
                        $convert: {
                          input: { $arrayElemAt: ['$$parts', 1] },
                          to: 'int',
                          onError: 0
                        }
                      }, 60] },
                      {
                        $convert: {
                          input: { $arrayElemAt: ['$$parts', 2] },
                          to: 'int',
                          onError: 0
                        }
                      }
                    ]
                  }
                }
              },
              else: 0
            }
          }
        }
      },
      {
        $match: {
          extension: { $ne: '', $ne: null },
          callType: 'outgoing'
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

// @desc    Get area codes with call statistics  
// @access  Private
router.get('/area-codes', auth, checkPermission('viewCallLogs'), async (req, res) => {
  try {
    // Validate query parameters with a route-specific schema
    const areaCodesQuerySchema = Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(1000).default(50),
      sortBy: Joi.string().valid('totalCalls', 'areaCode', 'state', 'totalDuration', 'totalCost').default('totalCalls'),
      sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
      search: Joi.string().allow('').optional().default(''),
      state: Joi.string().allow('').optional(),
      dateFrom: Joi.alternatives().try(
        Joi.date(),
        Joi.string().isoDate()
      ).optional(),
      dateTo: Joi.alternatives().try(
        Joi.date(),
        Joi.string().isoDate()
      ).optional(),
      collection: Joi.string().valid('cdrs_143.198.0.104', 'cdrs_167.71.120.52').optional().default(process.env.MONGODB_COLLECTION1)
    });

    const { error, value } = areaCodesQuerySchema.validate(req.query);
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
      state,
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

    // Date filtering - use raw database field names
    if (dateFrom || dateTo) {
      matchConditions['time-start'] = {};
      if (dateFrom) {
        try {
          const fromDate = new Date(dateFrom);
          if (!isNaN(fromDate.getTime())) {
            matchConditions['time-start'].$gte = fromDate;
          }
        } catch (error) {
          console.warn('Invalid dateFrom format:', dateFrom);
        }
      }
      if (dateTo) {
        try {
          const toDate = new Date(dateTo);
          if (!isNaN(toDate.getTime())) {
            matchConditions['time-start'].$lte = toDate;
          }
        } catch (error) {
          console.warn('Invalid dateTo format:', dateTo);
        }
      }
    }

    console.log('🔍 Match conditions:', JSON.stringify(matchConditions, null, 2));

    // Robust aggregation pipeline that derives fields from raw CDR columns
    const pipeline = [
      // Optional date filtering (handle string dates in database format)
      {
        $match: (() => {
          const q = {};
          if (dateFrom || dateTo) {
            q['time-start'] = {};
            if (dateFrom) {
              try {
                const fromDate = new Date(dateFrom);
                if (!isNaN(fromDate.getTime())) {
                  // Convert to database string format: "YYYY/MM/DD HH:mm:ss"
                  const fromStr = fromDate.getFullYear() + '/' +
                                 String(fromDate.getMonth() + 1).padStart(2, '0') + '/' +
                                 String(fromDate.getDate()).padStart(2, '0') + ' ' +
                                 String(fromDate.getHours()).padStart(2, '0') + ':' +
                                 String(fromDate.getMinutes()).padStart(2, '0') + ':' +
                                 String(fromDate.getSeconds()).padStart(2, '0');
                  q['time-start'].$gte = fromStr;
                }
              } catch (error) {
                console.warn('Invalid dateFrom format:', dateFrom);
              }
            }
            if (dateTo) {
              try {
                const toDate = new Date(dateTo);
                if (!isNaN(toDate.getTime())) {
                  // Convert to database string format: "YYYY/MM/DD HH:mm:ss"
                  const toStr = toDate.getFullYear() + '/' +
                               String(toDate.getMonth() + 1).padStart(2, '0') + '/' +
                               String(toDate.getDate()).padStart(2, '0') + ' ' +
                               String(toDate.getHours()).padStart(2, '0') + ':' +
                               String(toDate.getMinutes()).padStart(2, '0') + ':' +
                               String(toDate.getSeconds()).padStart(2, '0');
                  q['time-start'].$lte = toStr;
                }
              } catch (error) {
                console.warn('Invalid dateTo format:', dateTo);
              }
            }
          }
          return q;
        })()
      },
      // Derive fields from raw CDR document
      {
        $addFields: {
          fromNumberRaw: { $ifNull: ["$from-no", ""] },
          toNumberRaw: { $ifNull: ["$to-no", ""] }
        }
      },
      // Determine callType using from-no heuristic
      {
        $addFields: {
          callType: {
            $cond: {
              if: { $regexMatch: { input: "$fromNumberRaw", regex: /^Ext\./ } },
              then: "outgoing",
              else: {
                $cond: {
                  if: { $regexMatch: { input: "$fromNumberRaw", regex: /^\+?\d/ } },
                  then: "incoming",
                  else: "outgoing"
                }
              }
            }
          }
        }
      },
      // Only outgoing
      { $match: { callType: "outgoing" } },
      // Clean destination number and extract 3-digit area code (match CallLogsPage logic)
      {
        $addFields: {
          cleanTo: {
            $replaceAll: {
              input: {
                $replaceAll: {
                  input: {
                    $replaceAll: {
                      input: {
                        $replaceAll: {
                          input: {
                            $replaceAll: { input: { $toString: "$toNumberRaw" }, find: "+", replacement: "" }
                          },
                          find: " ", replacement: ""
                        }
                      },
                      find: "-", replacement: ""
                    }
                  },
                  find: "(", replacement: ""
                }
              },
              find: ")", replacement: ""
            }
          }
        }
      },
      // Compute durationSeconds and numeric cost
      {
        $addFields: {
          // Use same duration calculation as Call Logs route
          durationSeconds: {
            $cond: {
              if: { $and: [ { $ne: ["$duration", null] }, { $ne: ["$duration", ""] } ] },
              then: {
                $let: {
                  vars: {
                    parts: { $split: [{ $toString: "$duration" }, ":"] }
                  },
                  in: {
                    $cond: {
                      if: { $eq: [{ $size: "$$parts" }, 3] },
                      then: {
                        $add: [
                          { $multiply: [{ $toInt: { $arrayElemAt: ["$$parts", 0] } }, 3600] },
                          { $multiply: [{ $toInt: { $arrayElemAt: ["$$parts", 1] } }, 60] },
                          { $toInt: { $arrayElemAt: ["$$parts", 2] } }
                        ]
                      },
                      else: 0
                    }
                  }
                }
              },
              else: {
                $cond: {
                  if: { $and: [ { $ne: ["$time-start", null] }, { $ne: ["$time-end", null] } ] },
                  then: {
                    $floor: {
                      $divide: [
                        { $subtract: [
                          { $convert: { input: "$time-end", to: "date", onError: null } },
                          { $convert: { input: "$time-start", to: "date", onError: null } }
                        ]}, 
                        1000
                      ]
                    }
                  },
                  else: 0
                }
              }
            }
          },
          // Parse bill-cost using $convert with safe fallback (avoid string symbol handling)
          costNum: {
            $convert: { input: { $toString: "$bill-cost" }, to: "double", onError: 0, onNull: 0 }
          }
        }
      },
      {
        $addFields: {
          extractedAreaCode: {
            $cond: {
              if: { $gte: [{ $strLenCP: "$cleanTo" }, 5] },
              then: { $substr: ["$cleanTo", 2, 3] },
              else: null
            }
          }
        }
      },
      { $match: { extractedAreaCode: { $ne: null, $ne: "" } } },
      {
        $group: {
          _id: "$extractedAreaCode",
          totalCalls: { $sum: 1 },
          totalDuration: { $sum: "$durationSeconds" },
          totalCost: { $sum: "$costNum" }
        }
      },
      { $addFields: { areaCode: "$_id" } },
      { $project: { _id: 0, areaCode: 1, totalCalls: 1, totalDuration: 1, totalCost: 1 } }
    ];

    // Execute aggregation (grouped results only)
    const startTime = Date.now();
    const groupedAreas = await CDR.aggregate(pipeline);
    const endTime = Date.now();

    // Map area codes to rough US state names and compute percentage
    const STATE_MAP = {
      California: new Set(['209','213','279','310','323','341','369','408','415','424','442','510','530','559','562','619','626','650','657','661','669','707','714','747','760','805','818','820','831','840','858','909','916','925','926','935','949','951']),
      New_York: new Set(['212','315','332','347','516','518','585','607','631','646','680','716','718','838','845','914','917','929','934']),
      Florida: new Set(['239','305','321','324','352','386','407','448','561','645','689','727','728','754','772','786','813','850','863','904','927','941','954']),
      Arizona: new Set(['480','520','602','623','928']),
      Ohio: new Set(['216','220','234','283','326','330','380','419','436','440','513','567','614','740','937']),
      Puerto_Rico: new Set(['787','939']),
      Texas: new Set(['210','214','254','281','325','346','361','409','430','432','469','512','682','713','726','737','806','817','830','832','903','915','936','940','945','956','972','979']),
      Illinois: new Set(['217','224','309','312','331','447','464','618','630','708','730','773','779','815','847','872'])
    };

    function lookupState(code) {
      if (!code) return 'Unknown';
      for (const [state, set] of Object.entries(STATE_MAP)) {
        if (set.has(String(code))) return state.replace('_', ' ');
      }
      return 'Unknown';
    }

    const totalCallsAcrossAllAreas = groupedAreas.reduce((sum, a) => sum + (a.totalCalls || 0), 0);
    let areaCodes = groupedAreas.map(a => ({
      areaCode: a.areaCode,
      totalCalls: a.totalCalls,
      totalDuration: a.totalDuration || 0,
      totalCost: a.totalCost || 0,
      state: lookupState(a.areaCode),
      percentage: totalCallsAcrossAllAreas > 0 ? Math.round((a.totalCalls / totalCallsAcrossAllAreas) * 10000) / 100 : 0
    }));

    // State filtering (from URL parameter)
    if (state) {
      areaCodes = areaCodes.filter(a => 
        (a.state || '').toLowerCase() === state.toLowerCase()
      );
    }

    // Search filtering (client-like): by areaCode or state
    const searchLower = (search || '').toString().toLowerCase();
    if (searchLower) {
      areaCodes = areaCodes.filter(a =>
        a.areaCode.toLowerCase().includes(searchLower) ||
        (a.state || '').toLowerCase().includes(searchLower)
      );
    }

    // Sorting
    areaCodes.sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'totalCalls') {
        cmp = (a.totalCalls - b.totalCalls);
      } else if (sortBy === 'areaCode') {
        cmp = a.areaCode.localeCompare(b.areaCode);
      } else if (sortBy === 'state') {
        cmp = (a.state || '').localeCompare(b.state || '');
      } else if (sortBy === 'totalDuration') {
        cmp = (a.totalDuration - b.totalDuration);
      } else if (sortBy === 'totalCost') {
        cmp = (a.totalCost - b.totalCost);
      }
      return sortOrder === 'asc' ? cmp : -cmp;
    });

    // Pagination
    const areaCodeCount = areaCodes.length;
    const totalPages = Math.ceil(areaCodeCount / limit);
    const startIndex = (page - 1) * limit;
    const paginated = areaCodes.slice(startIndex, startIndex + limit);

    console.log(`✨ Area codes aggregation completed in ${endTime - startTime}ms`);
    console.log(`📊 Found ${paginated.length} area codes from ${totalCount} total records after filtering`);
    console.log('🎯 Sample area codes:', paginated.slice(0, 3));
    console.log('🔍 Sample raw aggregation result:', groupedAreas.slice(0, 2));

    res.json({
      success: true,
      areaCodes: paginated,
      pagination: {
        currentPage: page,
        totalPages,
        totalCount: areaCodeCount,
        limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
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

// @route   GET /api/cdr/raw-data
// @desc    Get raw CDR data with all MongoDB fields (no transformations)
// @access  Private
router.get('/raw-data', auth, checkPermission('viewCallLogs'), async (req, res) => {
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
      collection,
      extension,
      stateCode,
      minDurationSec,
      maxDurationSec,
      minCost,
      maxCost
    } = value;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build query using actual database field names
    const query = {};

    // Date range filter - handle string dates in database format "2025/09/08 15:43:15"
    if (dateFrom || dateTo) {
      query['time-start'] = {};
      if (dateFrom) {
        try {
          const fromDate = new Date(dateFrom);
          if (!isNaN(fromDate.getTime())) {
            // Convert to database string format: "YYYY/MM/DD HH:mm:ss"
            const fromStr = fromDate.getFullYear() + '/' +
                           String(fromDate.getMonth() + 1).padStart(2, '0') + '/' +
                           String(fromDate.getDate()).padStart(2, '0') + ' ' +
                           String(fromDate.getHours()).padStart(2, '0') + ':' +
                           String(fromDate.getMinutes()).padStart(2, '0') + ':' +
                           String(fromDate.getSeconds()).padStart(2, '0');
            query['time-start'].$gte = fromStr;
          }
        } catch (error) {
          console.warn('Invalid dateFrom format:', dateFrom);
        }
      }
      if (dateTo) {
        try {
          const toDate = new Date(dateTo);
          if (!isNaN(toDate.getTime())) {
            // Convert to database string format: "YYYY/MM/DD HH:mm:ss"
            const toStr = toDate.getFullYear() + '/' +
                         String(toDate.getMonth() + 1).padStart(2, '0') + '/' +
                         String(toDate.getDate()).padStart(2, '0') + ' ' +
                         String(toDate.getHours()).padStart(2, '0') + ':' +
                         String(toDate.getMinutes()).padStart(2, '0') + ':' +
                         String(toDate.getSeconds()).padStart(2, '0');
            query['time-start'].$lte = toStr;
          }
        } catch (error) {
          console.warn('Invalid dateTo format:', dateTo);
        }
      }
    }

    // Filter by termination reason
    if (terminationReason) query['reason-terminated'] = terminationReason;

    // Filter by trunk number
    if (trunkNumber) query['dial-no'] = trunkNumber;

    // Search functionality using actual database field names - expanded for raw data
    if (search) {
      query.$or = [
        { historyid: { $regex: search, $options: 'i' } },
        { callid: { $regex: search, $options: 'i' } },
        { 'call-id': { $regex: search, $options: 'i' } },
        { 'from-no': { $regex: search, $options: 'i' } },
        { 'to-no': { $regex: search, $options: 'i' } },
        { 'from-dn': { $regex: search, $options: 'i' } },
        { 'to-dn': { $regex: search, $options: 'i' } },
        { 'dial-no': { $regex: search, $options: 'i' } },
        { 'reason-terminated': { $regex: search, $options: 'i' } },
        { 'from-dispname': { $regex: search, $options: 'i' } },
        { 'to-dispname': { $regex: search, $options: 'i' } },
        { 'final-dispname': { $regex: search, $options: 'i' } },
        { 'bill-name': { $regex: search, $options: 'i' } },
        { chain: { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate skip value for pagination
    const skip = (page - 1) * limit;

    // Build sort object using actual database field names
    const sort = {};
    const sortFieldMap = {
      'startTime': 'time-start',
      'time-start': 'time-start',
      'duration': 'duration',
      'cost': 'bill-cost',
      'fromNumber': 'from-no',
      'from-no': 'from-no',
      'toNumber': 'to-no',
      'to-no': 'to-no',
      'historyId': 'historyid',
      'historyid': 'historyid',
      'durationSeconds': 'duration'
    };
    const actualSortField = sortFieldMap[sortBy] || sortBy || 'time-start';
    sort[actualSortField] = sortOrder === 'asc' ? 1 : -1;

    const isExport = String(req.query.export || '').toLowerCase() === 'true';

    // Get total count for pagination
    const totalCount = await CDR.countDocuments(query);
    
    // Execute query - return ALL fields from MongoDB (no field selection)
    const rawData = await CDR.find(query)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .lean()
      .allowDiskUse(true)
      .maxTimeMS(30000);

    const totalPages = Math.ceil(totalCount / limit);

    // CSV export handling
    if (isExport) {
      // Get all unique field names from the data
      const allFields = new Set();
      rawData.forEach(record => {
        Object.keys(record).forEach(key => allFields.add(key));
      });
      const fieldNames = Array.from(allFields).sort();

      // Build CSV with all fields
      const escapeCsv = (val) => {
        if (val === null || val === undefined) return '';
        const str = String(val);
        if (/[",\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
        return str;
      };

      const lines = [fieldNames.join(',')];
      for (const row of rawData) {
        const values = fieldNames.map(field => escapeCsv(row[field]));
        lines.push(values.join(','));
      }

      const csv = lines.join('\n');
      const filename = `raw-data-${new Date().toISOString().slice(0,10)}.csv`;
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.status(200).send(csv);
    }

    res.json({
      rawData: rawData,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalCount: totalCount,
        limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
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
    console.error('Get raw data error:', error);
    res.status(500).json({
      error: 'Server error while fetching raw data'
    });
  }
});

// Debug endpoint to check date ranges in database
router.get('/debug/date-range', auth, async (req, res) => {
  try {
    const { collection } = req.query;
    const CDR = getCDRModel(collection);
    
    // Get min and max dates from the database
    const minDate = await CDR.findOne({}, { 'time-start': 1 }).sort({ 'time-start': 1 }).lean();
    const maxDate = await CDR.findOne({}, { 'time-start': 1 }).sort({ 'time-start': -1 }).lean();
    
    // Get a few sample records to see the actual data structure
    const samples = await CDR.find({}, { 'time-start': 1, 'from-no': 1, 'to-no': 1 }).limit(5).lean();
    
    res.json({
      success: true,
      dateRange: {
        min: minDate ? minDate['time-start'] : null,
        max: maxDate ? maxDate['time-start'] : null
      },
      samples: samples.map(s => ({
        timeStart: s['time-start'],
        from: s['from-no'],
        to: s['to-no']
      })),
      totalRecords: await CDR.countDocuments({})
    });
  } catch (error) {
    console.error('Debug date range error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;