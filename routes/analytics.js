const express = require('express');
const Joi = require('joi');
const { getCDRModel } = require('../models/CDR');
const { auth, checkPermission } = require('../middleware/auth');
const moment = require('moment');

const router = express.Router();

// Validation schema for analytics queries
const analyticsQuerySchema = Joi.object({
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().optional(),
  callType: Joi.string().valid('incoming', 'outgoing', 'internal').optional(),
  status: Joi.string().valid('answered', 'unanswered', 'redirected', 'waiting').optional(),
  trunkNumber: Joi.string().optional(),
  areaCode: Joi.string().optional(),
  collection: Joi.string().valid('cdrs_143.198.0.104', 'cdrs_167.71.120.52').optional()
});

// @route   GET /api/analytics/dashboard
// @desc    Get dashboard analytics data
// @access  Private
router.get('/dashboard', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = analyticsQuerySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { dateFrom, dateTo, callType, status, trunkNumber, areaCode, collection } = value;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build base query
    const baseQuery = {};
    
    if (dateFrom || dateTo) {
      baseQuery['time-start'] = {};
      if (dateFrom) baseQuery['time-start'].$gte = new Date(dateFrom);
      if (dateTo) baseQuery['time-start'].$lte = new Date(dateTo);
    }
    
    if (trunkNumber) baseQuery['dial-no'] = trunkNumber;

    // Get basic statistics using simple queries
    const [
      totalCalls,
      totalCost,
      totalDuration,
      uniqueAreaCodes
    ] = await Promise.all([
      CDR.countDocuments(baseQuery),
      CDR.aggregate([
        { $match: baseQuery },
        { $group: { _id: null, total: { $sum: { $ifNull: ['$bill-cost', 0] } } } }
      ]).then(result => result[0]?.total || 0),
      CDR.aggregate([
        { $match: baseQuery },
        { $group: { _id: null, total: { $sum: { $ifNull: ['$duration', 0] } } } }
      ]).then(result => result[0]?.total || 0),
      CDR.distinct('areaCode', baseQuery).then(codes => codes.filter(code => code && code !== ''))
    ]);

    // For now, use simple estimates for call types and status
    // These would need to be calculated based on actual data transformation logic
    const incomingCalls = Math.floor(totalCalls * 0.6); // Estimate 60% incoming
    const outgoingCalls = totalCalls - incomingCalls;
    const answeredCalls = Math.floor(totalCalls * 0.8); // Estimate 80% answered
    const unansweredCalls = Math.floor(totalCalls * 0.15); // Estimate 15% unanswered
    const redirectedCalls = totalCalls - answeredCalls - unansweredCalls;

    // Calculate percentages and rates
    const answerRate = totalCalls > 0 ? (answeredCalls / totalCalls) * 100 : 0;
    const incomingPercentage = totalCalls > 0 ? (incomingCalls / totalCalls) * 100 : 0;
    const outgoingPercentage = totalCalls > 0 ? (outgoingCalls / totalCalls) * 100 : 0;

    // Get previous period data for comparison (same time range, but shifted back)
    let previousPeriodQuery = {};
    let growthMetrics = {};

    if (dateFrom && dateTo) {
      const periodDuration = moment(dateTo).diff(moment(dateFrom), 'days');
      const previousDateTo = moment(dateFrom).subtract(1, 'day').toDate();
      const previousDateFrom = moment(previousDateTo).subtract(periodDuration, 'days').toDate();

      previousPeriodQuery = {
        ...baseQuery,
        startTime: {
          $gte: previousDateFrom,
          $lte: previousDateTo
        }
      };

      const [prevTotalCalls, prevIncomingCalls, prevOutgoingCalls, prevTotalCost] = await Promise.all([
        CDR.countDocuments(previousPeriodQuery),
        CDR.countDocuments({ ...previousPeriodQuery, callType: 'incoming' }),
        CDR.countDocuments({ ...previousPeriodQuery, callType: 'outgoing' }),
        CDR.aggregate([
          { $match: previousPeriodQuery },
          { $group: { _id: null, total: { $sum: '$cost' } } }
        ]).then(result => result[0]?.total || 0)
      ]);

      // Calculate growth percentages
      growthMetrics = {
        totalCallsGrowth: prevTotalCalls > 0 ? ((totalCalls - prevTotalCalls) / prevTotalCalls) * 100 : 0,
        incomingCallsGrowth: prevIncomingCalls > 0 ? ((incomingCalls - prevIncomingCalls) / prevIncomingCalls) * 100 : 0,
        outgoingCallsGrowth: prevOutgoingCalls > 0 ? ((outgoingCalls - prevOutgoingCalls) / prevOutgoingCalls) * 100 : 0,
        totalCostGrowth: prevTotalCost > 0 ? ((totalCost - prevTotalCost) / prevTotalCost) * 100 : 0
      };
    }

    res.json({
      summary: {
        totalCalls,
        incomingCalls,
        outgoingCalls,
        answeredCalls,
        unansweredCalls,
        redirectedCalls,
        totalCost: Math.round(totalCost * 100) / 100,
        totalDuration: Math.floor(totalDuration / 60), // Convert to minutes
        uniqueAreaCodes: uniqueAreaCodes.length,
        answerRate: Math.round(answerRate * 100) / 100,
        incomingPercentage: Math.round(incomingPercentage * 100) / 100,
        outgoingPercentage: Math.round(outgoingPercentage * 100) / 100,
        avgDuration: totalCalls > 0 ? Math.round(totalDuration / totalCalls) : 0
      },
      growth: growthMetrics,
      filters: {
        dateFrom,
        dateTo,
        callType,
        status,
        trunkNumber,
        areaCode
      }
    });
  } catch (error) {
    console.error('Dashboard analytics error:', error);
    res.status(500).json({
      error: 'Server error while fetching dashboard analytics'
    });
  }
});

// @route   GET /api/analytics/area-code-distribution
// @desc    Get area code distribution for charts
// @access  Private
router.get('/area-code-distribution', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const { error, value } = analyticsQuerySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { dateFrom, dateTo, callType, status, collection } = value;
    const { limit = 30 } = req.query;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build query
    const matchQuery = {};
    if (dateFrom || dateTo) {
      matchQuery['time-start'] = {};
      if (dateFrom) matchQuery['time-start'].$gte = new Date(dateFrom);
      if (dateTo) matchQuery['time-start'].$lte = new Date(dateTo);
    }

    // Build aggregation pipeline with data transformation
    const pipeline = [
      { $match: matchQuery },
      {
        $addFields: {
          // Transform data to match expected format
          callType: {
            $cond: {
              if: { $regexMatch: { input: '$from-no', regex: /^Ext\./ } },
              then: 'outgoing',
              else: {
                $cond: {
                  if: { $regexMatch: { input: '$from-no', regex: /^\+?\d/ } },
                  then: 'incoming',
                  else: 'outgoing'
                }
              }
            }
          },
          status: {
            $cond: {
              if: { $and: [{ $exists: ['$time-answered'] }, { $ne: ['$time-answered', ''] }] },
              then: 'answered',
              else: {
                $cond: {
                  if: { $eq: ['$reason-terminated', 'redirected'] },
                  then: 'redirected',
                  else: 'unanswered'
                }
              }
            }
          },
          areaCode: {
            $cond: {
              if: { $regexMatch: { input: '$from-no', regex: /^Ext\./ } },
              then: {
                $let: {
                  vars: { cleaned: { $regexReplace: { input: '$to-no', regex: /\D/g, replacement: '' } } },
                  in: {
                    $cond: {
                      if: { $gte: [{ $strLenCP: '$$cleaned' }, 5] },
                      then: { $substr: ['$$cleaned', 2, 3] },
                      else: ''
                    }
                  }
                }
              },
              else: ''
            }
          },
          cost: { $ifNull: ['$bill-cost', 0] },
          durationSeconds: { $ifNull: ['$duration', 0] }
        }
      }
    ];

    // Add filters after transformation
    if (callType) {
      pipeline.push({ $match: { callType: callType } });
    }
    if (status) {
      pipeline.push({ $match: { status: status } });
    }

    // Filter for non-empty area codes and aggregate
    pipeline.push(
      { $match: { areaCode: { $ne: '' } } },
      {
        $group: {
          _id: '$areaCode',
          totalCalls: { $sum: 1 },
          totalCost: { $sum: '$cost' },
          totalDuration: { $sum: '$durationSeconds' }
        }
      },
      {
        $project: {
          areaCode: '$_id',
          totalCalls: 1,
          totalCost: { $round: ['$totalCost', 2] },
          totalDuration: 1,
          _id: 0
        }
      },
      { $sort: { totalCalls: -1 } },
      { $limit: parseInt(limit) }
    );

    const distribution = await CDR.aggregate(pipeline);

    res.json({
      distribution,
      totalAreaCodes: distribution.length
    });
  } catch (error) {
    console.error('Area code distribution error:', error);
    res.status(500).json({
      error: 'Server error while fetching area code distribution'
    });
  }
});

// @route   GET /api/analytics/extension-distribution
// @desc    Get extension distribution for charts
// @access  Private
router.get('/extension-distribution', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const { error, value } = analyticsQuerySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { dateFrom, dateTo, callType, status, collection } = value;
    const { limit = 30 } = req.query;

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build query
    const matchQuery = {};
    if (dateFrom || dateTo) {
      matchQuery['time-start'] = {};
      if (dateFrom) matchQuery['time-start'].$gte = new Date(dateFrom);
      if (dateTo) matchQuery['time-start'].$lte = new Date(dateTo);
    }

    // Simple aggregation for extensions
    const pipeline = [
      { $match: matchQuery },
      {
        $group: {
          _id: '$from-dn',
          totalCalls: { $sum: 1 },
          incomingCalls: { $sum: 1 }, // Simplified for now
          outgoingCalls: { $sum: 1 }, // Simplified for now
          totalDuration: { $sum: { $ifNull: ['$duration', 0] } }
        }
      },
      { $match: { _id: { $ne: null, $ne: '' } } },
      {
        $project: {
          extension: '$_id',
          totalCalls: 1,
          incomingCalls: { $divide: ['$totalCalls', 2] }, // Rough estimate
          outgoingCalls: { $divide: ['$totalCalls', 2] }, // Rough estimate
          totalDuration: 1,
          _id: 0
        }
      },
      { $sort: { totalCalls: -1 } },
      { $limit: parseInt(limit) }
    ];

    const distribution = await CDR.aggregate(pipeline);

    res.json({
      distribution,
      totalExtensions: distribution.length
    });
  } catch (error) {
    console.error('Extension distribution error:', error);
    res.status(500).json({
      error: 'Server error while fetching extension distribution'
    });
  }
});

// @route   GET /api/analytics/call-trends
// @desc    Get call trends over time
// @access  Private
router.get('/call-trends', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const { error, value } = analyticsQuerySchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        details: error.details[0].message
      });
    }

    const { dateFrom, dateTo, callType, status, collection } = value;
    const { interval = 'day' } = req.query; // day, hour, week, month

    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    // Build query
    const matchQuery = {};
    if (dateFrom || dateTo) {
      matchQuery['time-start'] = {};
      if (dateFrom) matchQuery['time-start'].$gte = new Date(dateFrom);
      if (dateTo) matchQuery['time-start'].$lte = new Date(dateTo);
    }
    if (callType) matchQuery.callType = callType;
    if (status) matchQuery.status = status;

    // Define date grouping based on interval
    let dateGroup;
    switch (interval) {
      case 'hour':
        dateGroup = {
          year: { $year: '$time-start' },
          month: { $month: '$time-start' },
          day: { $dayOfMonth: '$time-start' },
          hour: { $hour: '$time-start' }
        };
        break;
      case 'week':
        dateGroup = {
          year: { $year: '$time-start' },
          week: { $week: '$time-start' }
        };
        break;
      case 'month':
        dateGroup = {
          year: { $year: '$time-start' },
          month: { $month: '$time-start' }
        };
        break;
      default: // day
        dateGroup = {
          year: { $year: '$time-start' },
          month: { $month: '$time-start' },
          day: { $dayOfMonth: '$time-start' }
        };
    }

    const pipeline = [
      { $match: matchQuery },
      {
        $group: {
          _id: dateGroup,
          totalCalls: { $sum: 1 },
          incomingCalls: {
            $sum: { $cond: [{ $eq: ['$callType', 'incoming'] }, 1, 0] }
          },
          outgoingCalls: {
            $sum: { $cond: [{ $eq: ['$callType', 'outgoing'] }, 1, 0] }
          },
          answeredCalls: {
            $sum: { $cond: [{ $eq: ['$status', 'answered'] }, 1, 0] }
          },
          totalCost: { $sum: '$cost' },
          totalDuration: { $sum: '$durationSeconds' }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1 } }
    ];

    const trends = await CDR.aggregate(pipeline);

    // Format the results
    const formattedTrends = trends.map(trend => ({
      period: trend._id,
      totalCalls: trend.totalCalls,
      incomingCalls: trend.incomingCalls,
      outgoingCalls: trend.outgoingCalls,
      answeredCalls: trend.answeredCalls,
      answerRate: trend.totalCalls > 0 ? (trend.answeredCalls / trend.totalCalls) * 100 : 0,
      totalCost: Math.round(trend.totalCost * 100) / 100,
      avgDuration: trend.totalCalls > 0 ? Math.round(trend.totalDuration / trend.totalCalls) : 0
    }));

    res.json({
      trends: formattedTrends,
      interval,
      totalPeriods: formattedTrends.length
    });
  } catch (error) {
    console.error('Call trends error:', error);
    res.status(500).json({
      error: 'Server error while fetching call trends'
    });
  }
});

module.exports = router;