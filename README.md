![Banner](https://www.upload.ee/image/17406748/dprotection.png)

# Express DDoS Protection System

Advanced DDoS protection middleware for Express.js applications with comprehensive security features.

## Features

- 🛡️ **DDoS Protection**
  - Rate limiting
  - Burst detection
  - Anomaly detection
  - Request pattern analysis

- 🔒 **Security Features**
  - SQL Injection protection
  - XSS (Cross-Site Scripting) protection
  - Path Traversal detection
  - Request size limiting
  - HTTP method validation
  - IP blocking/allowing
  - Request sanitization

- 📊 **Monitoring**
  - Detailed logging
  - Request statistics
  - Attack detection metrics
  - Real-time monitoring

## Installation

1. Clone the repository:
```bash
git clone https://github.com/queaxtra/dprotection.git
cd dprotection
```

2. Install dependencies:
```bash
npm install
# or
bun install
```

3. Create logs directory:
```bash
mkdir logs
```

## Project Structure

```
src/
├── protection/
│   ├── interfaces/
│   │   └── types.ts         # Type definitions
│   ├── services/
│   │   └── protection.service.ts  # Core protection logic
│   └── middleware.ts        # Express middleware
└── index.ts                 # Example Express server
```

## Configuration

The protection system can be configured through the `Guard.config()` method:

```typescript
Guard.config({
  routes: {
    '/api': { limit: 50, window: 60000 },    // 50 requests per minute
    '/login': { limit: 10, window: 60000 }   // 10 requests per minute
  },
  burst: 10,        // Max burst requests
  time: 1000,       // Burst window in ms
  score: 2.5        // Anomaly detection threshold
})
```

### Configuration Options

- `window`: Time window for rate limiting (ms)
- `limit`: Maximum requests per window
- `size`: Maximum request size in bytes
- `methods`: Allowed HTTP methods
- `rules`: Pattern matching rules for attack detection
- `blocked`: Blocked IP addresses
- `allowed`: Whitelisted IP addresses
- `burst`: Maximum burst requests
- `time`: Burst detection window
- `score`: Anomaly detection sensitivity

## Usage

1. Basic setup:

```typescript
import express from 'express'
import { secure, protect, limit } from './src/protection/middleware'
import { Guard } from './src/protection/services/protection.service'

const app = express()

// Apply middleware
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))
app.use(secure)
app.use(limit)
app.use(protect)

// Configure protection
Guard.config({
  routes: {
    '/api': { limit: 50, window: 60000 },
    '/login': { limit: 10, window: 60000 }
  }
})
```

2. Start the server:
```bash
bun run index.ts
```

## Testing

You can test the protection system using curl commands:

1. Normal request:
```bash
curl http://localhost:3000/api
```

2. Rate limit test:
```bash
for i in {1..20}; do curl http://localhost:3000/api; done
```

3. SQL Injection test:
```bash
curl -X POST http://localhost:3000/api -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users; DROP TABLE users;"}'
```

4. XSS test:
```bash
curl -X POST http://localhost:3000/api -H "Content-Type: application/json" \
  -d '{"data": "<script>alert(1)</script>"}'
```

5. Path Traversal test:
```bash
curl "http://localhost:3000/api?file=../../etc/passwd"
```

## Security Measures

### 1. Rate Limiting
- Per-route request limits
- Configurable time windows
- Burst detection

### 2. Attack Pattern Detection
- SQL injection patterns
- XSS attempts
- Path traversal
- Malicious payloads

### 3. Request Validation
- Size limits
- Method validation
- Content sanitization
- Header validation

### 4. Anomaly Detection
- Request interval analysis
- Pattern recognition
- Entropy calculation
- Statistical analysis

### 5. IP Management
- IP blocking
- Whitelisting
- Automatic ban/unban

## Logging

Logs are stored in `logs/security.log` with the following information:
- Timestamp
- Request details
- Attack attempts
- System events
- Performance metrics

## API Reference

### Guard Class

```typescript
class Guard {
  // Configure protection settings
  static config(cfg: Partial<Config>): void

  // Get current statistics
  static stats_now(): Stats

  // Check request validity
  static check_request(
    ip: string,
    type: string,
    data: string,
    bytes: number,
    path: string
  ): Promise<boolean>
}
```

### Middleware Functions

```typescript
// Security headers and basic protection
export const secure: Array<RequestHandler>

// Rate limiting
export const limit: RequestHandler

// Main protection middleware
export const protect: RequestHandler
```

## Performance Considerations

- Efficient request processing
- Minimal memory footprint
- Optimized pattern matching
- Smart caching of request data
- Automatic cleanup of old data

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License