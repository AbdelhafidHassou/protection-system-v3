// MongoDB initialization script
db = db.getSiblingDB('fraud_detection');

// Create collections with validation
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['email', 'created_at'],
      properties: {
        email: {
          bsonType: 'string',
          pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
        },
        created_at: {
          bsonType: 'date'
        }
      }
    }
  }
});

db.createCollection('auth_events', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['email', 'timestamp', 'success'],
      properties: {
        email: {
          bsonType: 'string'
        },
        timestamp: {
          bsonType: 'date'
        },
        success: {
          bsonType: 'bool'
        }
      }
    }
  }
});

db.createCollection('session_events', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['email', 'session_id', 'timestamp', 'action'],
      properties: {
        email: {
          bsonType: 'string'
        },
        session_id: {
          bsonType: 'string'
        },
        timestamp: {
          bsonType: 'date'
        },
        action: {
          bsonType: 'string'
        }
      }
    }
  }
});

db.createCollection('risk_assessments');
db.createCollection('feedback');

// Create indexes
db.users.createIndex({ email: 1 }, { unique: true });
db.auth_events.createIndex({ email: 1, timestamp: -1 });
db.session_events.createIndex({ email: 1, timestamp: -1 });
db.risk_assessments.createIndex({ 'request.email': 1, created_at: -1 });

print('MongoDB initialization completed');