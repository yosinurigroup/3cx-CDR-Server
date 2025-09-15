const express = require('express');
const { getCDRModel } = require('../models/CDR');
const { auth, checkPermission } = require('../middleware/auth');

const router = express.Router();

// @route   GET /api/dashboard/stats
// @desc    Get comprehensive dashboard statistics using aggregation pipelines
// @access  Private
router.get('/stats', auth, checkPermission('viewAnalytics'), async (req, res) => {
  try {
    const {
      collection,
      dateFrom,
      dateTo,
      callType,
      extension,
      areaCode,
      minDurationSec,
      maxDurationSec,
      minCost,
      maxCost
    } = req.query;
    
    // Get the appropriate CDR model based on collection parameter
    const CDR = getCDRModel(collection);

    console.log(`🚀 Processing dashboard stats for collection: ${collection}`);
    const startTime = Date.now();

    // Build dynamic stages for powerful filtering - handle string dates in database format
    const dateMatch = {};
    if (dateFrom || dateTo) {
      dateMatch['time-start'] = {};
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
            dateMatch['time-start'].$gte = fromStr;
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
            dateMatch['time-start'].$lte = toStr;
          }
        } catch (error) {
          console.warn('Invalid dateTo format:', dateTo);
        }
      }
    }

    const derivedMatch = {};
    if (callType) derivedMatch.callType = callType;
    if (extension) derivedMatch.extension = { $regex: String(extension), $options: 'i' };
    if (areaCode) derivedMatch.areaCode = String(areaCode);
    if (typeof minDurationSec !== 'undefined') derivedMatch.durationSeconds = { ...(derivedMatch.durationSeconds || {}), $gte: Number(minDurationSec) || 0 };
    if (typeof maxDurationSec !== 'undefined') derivedMatch.durationSeconds = { ...(derivedMatch.durationSeconds || {}), $lte: Number(maxDurationSec) || 0 };
    if (typeof minCost !== 'undefined') derivedMatch.cost = { ...(derivedMatch.cost || {}), $gte: Number(minCost) || 0 };
    if (typeof maxCost !== 'undefined') derivedMatch.cost = { ...(derivedMatch.cost || {}), $lte: Number(maxCost) || 0 };

    // Robust date range match on converted date field (works whether time-start is string or Date)
    const timeStartRangeMatch = {};
    if (dateFrom || dateTo) {
      timeStartRangeMatch.timeStartDate = {};
      if (dateFrom) {
        try {
          const fromDate = new Date(dateFrom);
          if (!isNaN(fromDate.getTime())) {
            timeStartRangeMatch.timeStartDate.$gte = fromDate;
          }
        } catch (error) {
          console.warn('Invalid dateFrom format:', dateFrom);
        }
      }
      if (dateTo) {
        try {
          const toDate = new Date(dateTo);
          if (!isNaN(toDate.getTime())) {
            timeStartRangeMatch.timeStartDate.$lte = toDate;
          }
        } catch (error) {
          console.warn('Invalid dateTo format:', dateTo);
        }
      }
    }

    // MAGIC AGGREGATION PIPELINE 🎯
    // This pipeline processes all records efficiently and applies filters
    const pipeline = [
      // Optional early match for raw date range
      ...(Object.keys(dateMatch).length ? [{ $match: dateMatch }] : []),
      {
        $addFields: {
          // Transform call type based on from-no field
          callType: {
            $cond: {
              if: { $regexMatch: { input: { $ifNull: ['$from-no', ''] }, regex: "^Ext\\." } },
              then: 'outgoing',
              else: {
                $cond: {
                  if: { $regexMatch: { input: { $ifNull: ['$from-no', ''] }, regex: "^\\+?\\d" } },
                  then: 'incoming',
                  else: 'outgoing'
                }
              }
            }
          },
          // Use existing areaCode field or extract from to-no for outgoing calls
          areaCode: {
            $cond: {
              if: { $and: [
                { $ne: [{ $ifNull: ['$areaCode', ''] }, ''] },
                { $ne: [{ $ifNull: ['$areaCode', ''] }, null] }
              ]},
              then: '$areaCode',
              else: {
                $cond: {
                  if: { $regexMatch: { input: { $ifNull: ['$from-no', ''] }, regex: "^Ext\\." } },
                  then: {
                    $substr: [
                      { $replaceAll: { input: { $ifNull: ['$to-no', ''] }, find: "+", replacement: "" } },
                      2, 3
                    ]
                  },
                  else: ''
                }
              }
            }
          },
          // Clean extension field
          extension: { $ifNull: ['$from-dn', ''] },
          // Clean cost field
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
          // Clean duration field - convert string duration to seconds
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
      // Safe date conversion for robust range filtering regardless of field type
      {
        $addFields: {
          timeStartDate: {
            $convert: { input: '$time-start', to: 'date', onError: null, onNull: null }
          }
        }
      },
      ...(Object.keys(timeStartRangeMatch).length ? [{ $match: timeStartRangeMatch }] : []),
      // Derived match (callType, areaCode, extension, duration, cost)
      ...(Object.keys(derivedMatch).length ? [{ $match: derivedMatch }] : []),
      {
        $facet: {
          // Overall statistics
          totalStats: [
            {
              $group: {
                _id: null,
                totalCalls: { $sum: 1 },
                incomingCalls: { $sum: { $cond: [{ $eq: ['$callType', 'incoming'] }, 1, 0] } },
                outgoingCalls: { $sum: { $cond: [{ $eq: ['$callType', 'outgoing'] }, 1, 0] } },
                totalCost: { $sum: '$cost' },
                totalDuration: { $sum: '$durationSeconds' },
                avgDuration: { $avg: '$durationSeconds' }
              }
            }
          ],
          // Unique area codes count
          uniqueAreaCodes: [
            { $match: { areaCode: { $ne: '', $ne: null } } },
            { $group: { _id: '$areaCode' } },
            { $count: 'count' }
          ],
          // Unique extensions count (outgoing calls only)
          uniqueExtensions: [
            { $match: { extension: { $ne: '', $ne: null }, callType: 'outgoing' } },
            { $group: { _id: '$extension' } },
            { $count: 'count' }
          ],
          // Top 30 area codes distribution
          areaCodeDistribution: [
            { $match: { areaCode: { $ne: '', $ne: null, $exists: true } } },
            {
              $group: {
                _id: '$areaCode',
                count: { $sum: 1 },
                totalCost: { $sum: '$cost' },
                totalDuration: { $sum: '$durationSeconds' }
              }
            },
            { $sort: { count: -1 } },
            { $limit: 30 },
            {
              $project: {
                areaCode: '$_id',
                count: 1,
                totalCost: { $round: ['$totalCost', 2] },
                totalDuration: 1,
                _id: 0
              }
            }
          ],
          // Top 30 extensions distribution (outgoing calls only)
          extensionDistribution: [
            { $match: { extension: { $ne: '', $ne: null }, callType: 'outgoing' } },
            {
              $group: {
                _id: '$extension',
                count: { $sum: 1 },
                incomingCalls: { $sum: { $cond: [{ $eq: ['$callType', 'incoming'] }, 1, 0] } },
                outgoingCalls: { $sum: { $cond: [{ $eq: ['$callType', 'outgoing'] }, 1, 0] } },
                totalDuration: { $sum: '$durationSeconds' }
              }
            },
            { $sort: { count: -1 } },
            { $limit: 30 },
            {
              $project: {
                extension: '$_id',
                count: 1,
                incomingCalls: 1,
                outgoingCalls: 1,
                totalDuration: 1,
                _id: 0
              }
            }
          ]
        }
      }
    ];

    // Execute the MAGIC pipeline 🎯
    const results = await CDR.aggregate(pipeline);
    const endTime = Date.now();
    
    console.log(`✨ Dashboard aggregation completed in ${endTime - startTime}ms`);
    console.log(`📊 Processed ${results[0].totalStats[0]?.totalCalls || 0} total records`);

    // Extract results
    const totalStats = results[0].totalStats[0] || {
      totalCalls: 0,
      incomingCalls: 0,
      outgoingCalls: 0,
      totalCost: 0,
      totalDuration: 0,
      avgDuration: 0
    };

    const uniqueAreaCodesCount = results[0].uniqueAreaCodes[0]?.count || 0;
    const uniqueExtensionsCount = results[0].uniqueExtensions[0]?.count || 0;
    const areaCodeDistribution = results[0].areaCodeDistribution || [];
    const extensionDistribution = results[0].extensionDistribution || [];

    // Calculate percentages
    const incomingPercentage = totalStats.totalCalls > 0 ? (totalStats.incomingCalls / totalStats.totalCalls) * 100 : 0;
    const outgoingPercentage = totalStats.totalCalls > 0 ? (totalStats.outgoingCalls / totalStats.totalCalls) * 100 : 0;

    // Add percentages to distributions
    const areaCodeDistributionWithPercentage = areaCodeDistribution.map(item => ({
      ...item,
      percentage: totalStats.totalCalls > 0 ? (item.count / totalStats.totalCalls) * 100 : 0
    }));

    const extensionDistributionWithPercentage = extensionDistribution.map(item => ({
      ...item,
      percentage: totalStats.totalCalls > 0 ? (item.count / totalStats.totalCalls) * 100 : 0
    }));

    res.json({
      success: true,
      processingTime: endTime - startTime,
      recordsProcessed: totalStats.totalCalls,
      data: {
        summary: {
          totalCalls: totalStats.totalCalls,
          incomingCalls: totalStats.incomingCalls,
          outgoingCalls: totalStats.outgoingCalls,
          uniqueAreaCodes: uniqueAreaCodesCount,
          uniqueExtensions: uniqueExtensionsCount,
          totalCost: Math.round(totalStats.totalCost * 100) / 100,
          totalDuration: totalStats.totalDuration,
          avgDuration: Math.round(totalStats.avgDuration || 0),
          incomingPercentage: Math.round(incomingPercentage * 100) / 100,
          outgoingPercentage: Math.round(outgoingPercentage * 100) / 100
        },
        areaCodeDistribution: areaCodeDistributionWithPercentage,
        extensionDistribution: extensionDistributionWithPercentage
      }
    });

  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error while fetching dashboard statistics',
      details: error.message
    });
  }
});

module.exports = router;