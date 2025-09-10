const mongoose = require('mongoose');

const cdrSchema = new mongoose.Schema({
  historyId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  startTime: {
    type: Date,
    required: true,
    index: true
  },
  endTime: {
    type: Date,
    index: true
  },
  duration: {
    type: String, // Format: "00:00:00"
    default: null
  },
  durationSeconds: {
    type: Number,
    default: 0,
    index: true
  },
  fromNumber: {
    type: String,
    required: true,
    index: true
  },
  toNumber: {
    type: String,
    required: true,
    index: true
  },
  terminationReason: {
    type: String,
    enum: [
      'answered',
      'declined',
      'busy',
      'no_answer',
      'failed',
      'cancelled',
      'src_participant_terminated',
      'dst_participant_terminated',
      'redirected',
      'waiting'
    ],
    default: 'answered',
    index: true
  },
  cost: {
    type: Number,
    default: 0,
    min: 0
  },
  callType: {
    type: String,
    enum: ['incoming', 'outgoing', 'internal'],
    required: true,
    index: true
  },
  trunkNumber: {
    type: String,
    index: true
  },
  areaCode: {
    type: String,
    index: true
  },
  extension: {
    type: String,
    index: true
  },
  status: {
    type: String,
    enum: ['answered', 'unanswered', 'redirected', 'waiting'],
    default: 'answered',
    index: true
  },
  // Additional metadata
  serverIp: {
    type: String,
    index: true
  },
  recordingPath: {
    type: String,
    default: null
  },
  quality: {
    type: Number,
    min: 0,
    max: 5,
    default: null
  }
}, {
  timestamps: true
  // Collection will be set dynamically
});

// Indexes for better query performance
cdrSchema.index({ startTime: -1 });
cdrSchema.index({ callType: 1, startTime: -1 });
cdrSchema.index({ areaCode: 1, startTime: -1 });
cdrSchema.index({ terminationReason: 1, startTime: -1 });
cdrSchema.index({ fromNumber: 1, toNumber: 1 });

// Virtual for formatted duration
cdrSchema.virtual('formattedDuration').get(function() {
  if (!this.durationSeconds) return '00:00:00';
  
  const hours = Math.floor(this.durationSeconds / 3600);
  const minutes = Math.floor((this.durationSeconds % 3600) / 60);
  const seconds = this.durationSeconds % 60;
  
  return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
});

// Static method to get area code from phone number
cdrSchema.statics.extractAreaCode = function(phoneNumber) {
  if (!phoneNumber) return null;
  
  // Remove non-numeric characters
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  // Extract area code (assuming North American format)
  if (cleaned.length >= 10) {
    return cleaned.substring(0, 3);
  }
  
  return null;
};

// Pre-save middleware to extract area code and calculate duration
cdrSchema.pre('save', function(next) {
  // Extract area code from phone numbers
  if (!this.areaCode) {
    this.areaCode = this.constructor.extractAreaCode(this.fromNumber) || 
                   this.constructor.extractAreaCode(this.toNumber);
  }
  
  // Calculate duration in seconds if not provided
  if (this.startTime && this.endTime && !this.durationSeconds) {
    this.durationSeconds = Math.floor((this.endTime - this.startTime) / 1000);
  }
  
  // Set duration string format
  if (this.durationSeconds && !this.duration) {
    const hours = Math.floor(this.durationSeconds / 3600);
    const minutes = Math.floor((this.durationSeconds % 3600) / 60);
    const seconds = this.durationSeconds % 60;
    this.duration = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  }
  
  next();
});

// Create a function to get CDR model for specific collection
const getCDRModel = (collectionName) => {
  // Use the collection name from environment or parameter
  const collection = collectionName || process.env.MONGODB_COLLECTION1 || 'cdrs_143.198.0.104';
  
  // Create schema with specific collection name
  const dynamicSchema = cdrSchema.clone();
  dynamicSchema.set('collection', collection);
  
  // Return model with collection-specific name to avoid conflicts
  const modelName = `CDR_${collection.replace(/[^a-zA-Z0-9]/g, '_')}`;
  
  // Check if model already exists
  if (mongoose.models[modelName]) {
    return mongoose.models[modelName];
  }
  
  return mongoose.model(modelName, dynamicSchema, collection);
};

// Export both the schema and the function
module.exports = {
  getCDRModel,
  cdrSchema
};

// For backward compatibility, also export default model
module.exports.CDR = getCDRModel();