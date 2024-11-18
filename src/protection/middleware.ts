import { type Request, type Response, type NextFunction } from 'express'
import { Guard } from './services/protection.service'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import { createHash } from 'crypto'

export const secure = [
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: 'same-origin' },
    xssFilter: true,
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    originAgentCluster: true
  })
]

export const limit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false
})

const clean = (req: Request) => {
  const safe = {
    method: req.method,
    path: req.path,
    query: {},
    body: {},
    headers: {}
  }

  for (const [key, value] of Object.entries(req.query)) {
    if (typeof value === 'string') {
      safe.query[key] = value.replace(/[<>]/g, '')
    }
  }

  if (req.body && typeof req.body === 'object') {
    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value === 'string') {
        safe.body[key] = value.replace(/[<>]/g, '')
      }
    }
  }

  const allowed = ['user-agent', 'content-type', 'accept']
  for (const header of allowed) {
    const value = req.headers[header]
    if (value && typeof value === 'string') {
      safe.headers[header] = value
    }
  }

  return safe
}

const hash = (req: Request): string => {
  const data = JSON.stringify({
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body,
    ip: req.ip
  })
  return createHash('sha256').update(data).digest('hex')
}

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const start = Date.now()
    const id = hash(req).substr(0, 8)
    const safe = clean(req)

    console.log(`[${new Date().toISOString()}] Request ${id} from ${req.ip}`)

    const size = parseInt(req.headers['content-length'] || '0', 10)
    const data = JSON.stringify(safe)

    const ok = await Guard.check_request(
      req.ip || 'unknown',
      req.method,
      data,
      size,
      req.path
    )

    if (!ok) {
      const end = Date.now()
      console.log(`[${new Date().toISOString()}] Request ${id} blocked (${end - start}ms)`)
      
      res.status(429).json({
        error: 'Security Check Failed',
        message: 'Request blocked'
      })
      return
    }

    res.on('finish', () => {
      const end = Date.now()
      console.log(`[${new Date().toISOString()}] Request ${id} done (${end - start}ms)`)
    })

    next()
  } catch (error) {
    console.error('Protection error:', error)
    res.status(500).json({ error: 'Server Error' })
  }
}