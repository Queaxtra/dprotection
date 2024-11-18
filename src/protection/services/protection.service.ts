import { type Request, type Config, type Stats } from '../interfaces/types'
import winston from 'winston'
import { createHash } from 'crypto'

export class Guard {
  private static reqs = new Map<string, Request>()
  private static bans = new Set<string>()
  private static stats: Stats = {
    total: 0,
    blocked: 0,
    active: 0,
    patterns: 0,
    methods: 0,
    payloads: 0,
    alerts: 0,
    time: Date.now()
  }

  private static cfg: Config = {
    window: 60000,
    limit: 100,
    size: 10485760,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    rules: [
      'union.*select|insert.*into|delete.*from',
      'eval\\(|exec\\(|system\\(',
      '\\.\\.',
      '<script',
      'data:text/html',
      'base64'
    ],
    blocked: [],
    allowed: [],
    routes: {
      '/api': { limit: 50, window: 60000 },
      '/login': { limit: 10, window: 60000 }
    },
    burst: 10,
    time: 1000,
    score: 2.5,
    block: 3600000,
    reset: 3600000,
    max: 5
  }

  private static log = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: [
      new winston.transports.File({ filename: 'logs/security.log' }),
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      })
    ]
  })

  private static clean(): void {
    const now = Date.now()
    for (const [ip, req] of this.reqs) {
      if (now - req.time > this.cfg.window) {
        this.reqs.delete(ip)
      }
    }

    for (const ip of this.bans) {
      const req = this.reqs.get(ip)
      if (req && now - req.time > this.cfg.block) {
        this.bans.delete(ip)
        this.log.info(`IP unbanned: ${ip}`)
      }
    }

    this.stats.active = this.bans.size
  }

  private static async check(history: number[]): Promise<boolean> {
    if (history.length < 3) return false

    const gaps: number[] = []
    for (let i = 1; i < history.length; i++) {
      gaps.push(history[i] - history[i - 1])
    }

    const avg = gaps.reduce((a, b) => a + b, 0) / gaps.length
    const dev = Math.sqrt(
      gaps.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / gaps.length
    )
    const last = gaps[gaps.length - 1]

    const sudden = Math.abs(last - avg) > (dev * this.cfg.score)
    const bot = gaps.every(gap => Math.abs(gap - last) < 50)
    const low = this.entropy(gaps) < 1.0

    return sudden || (bot && gaps.length > 5) || low
  }

  private static entropy(gaps: number[]): number {
    const counts = new Map<number, number>()
    gaps.forEach(gap => {
      counts.set(gap, (counts.get(gap) || 0) + 1)
    })

    return -Array.from(counts.values())
      .map(count => {
        const p = count / gaps.length
        return p * Math.log2(p)
      })
      .reduce((a, b) => a + b, 0)
  }

  private static rules(content: string): boolean {
    try {
      const hash = createHash('sha256').update(content).digest('hex')
      
      for (const rule of this.cfg.rules) {
        const regex = new RegExp(rule, 'i')
        if (regex.test(content)) {
          this.log.warn(`Attack pattern: ${rule}, Hash: ${hash.substr(0, 8)}`)
          return false
        }
      }

      if (/<[^>]*>/.test(content) || /javascript:/i.test(content)) {
        this.log.warn(`XSS attempt, Hash: ${hash.substr(0, 8)}`)
        return false
      }

      if (/\.\.\/|\.\.\\/.test(content)) {
        this.log.warn(`Path attack, Hash: ${hash.substr(0, 8)}`)
        return false
      }

      return true
    } catch (error) {
      this.log.error('Rule check error:', error)
      return false
    }
  }

  private static size(bytes: number): boolean {
    if (bytes === 0) return true
    const ok = bytes <= this.cfg.size
    if (!ok) {
      this.log.warn(`Size violation: ${bytes} bytes`)
      this.stats.payloads++
    }
    return ok
  }

  private static method(type: string): boolean {
    const ok = this.cfg.methods.includes(type)
    if (!ok) {
      this.log.warn(`Method violation: ${type}`)
      this.stats.methods++
    }
    return ok
  }

  public static async check_request(
    ip: string, 
    type: string, 
    data: string, 
    bytes: number, 
    path: string
  ): Promise<boolean> {
    this.stats.total++
    this.clean()

    if (this.cfg.allowed.includes(ip)) return true

    if (this.bans.has(ip) || this.cfg.blocked.includes(ip)) {
      this.stats.blocked++
      return false
    }

    const now = Date.now()
    let req = this.reqs.get(ip) || {
      ip,
      time: now,
      count: 0,
      history: [],
      burst: 0,
      lastBurst: now,
      score: 0,
      patterns: 0,
      methods: 0,
      payloads: 0,
      total: 0,
      lastReset: now
    }

    if (req.lastReset && now - req.lastReset >= this.cfg.reset) {
      req.patterns = 0
      req.methods = 0
      req.payloads = 0
      req.total = 0
      req.lastReset = now
    }

    if (!this.method(type)) {
      req.methods++
      req.total++
    }

    if (!this.size(bytes)) {
      req.payloads++
      req.total++
    }

    if (!this.rules(data)) {
      req.patterns++
      req.total++
    }

    req.history.push(now)
    if (await this.check(req.history)) {
      this.stats.alerts++
      this.log.warn(`Anomaly: ${ip}`)
      this.bans.add(ip)
      return false
    }

    if (req.total >= this.cfg.max) {
      this.log.warn(`Max violations: ${ip}`)
      this.bans.add(ip)
      return false
    }

    const route = this.cfg.routes[path]
    const limit = route?.limit || this.cfg.limit
    const window = route?.window || this.cfg.window

    if (now - req.time > window) {
      req.time = now
      req.count = 1
    } else {
      req.count++
    }

    if (now - req.lastBurst <= this.cfg.time) {
      req.burst++
      if (req.burst > this.cfg.burst) {
        this.log.warn(`Burst limit: ${ip}`)
        this.bans.add(ip)
        return false
      }
    } else {
      req.burst = 1
      req.lastBurst = now
    }

    this.reqs.set(ip, req)
    return req.count <= limit
  }

  public static config(cfg: Partial<Config>): void {
    this.cfg = { ...this.cfg, ...cfg }
    this.log.info('Config updated')
  }

  public static stats_now(): Stats {
    return { ...this.stats }
  }
}