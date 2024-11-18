export interface Request {
  ip: string
  time: number
  count: number
  history: number[]
  burst: number
  lastBurst: number
  score: number
  patterns: number
  methods: number
  payloads: number
  total: number
  lastReset: number
}

export interface Route {
  limit: number
  window: number
}

export interface Config {
  window: number
  limit: number
  size: number
  methods: string[]
  rules: string[]
  blocked: string[]
  allowed: string[]
  routes: { [key: string]: Route }
  burst: number
  time: number
  score: number
  block: number
  reset: number
  max: number
}

export interface Stats {
  total: number
  blocked: number
  active: number
  patterns: number
  methods: number
  payloads: number
  alerts: number
  time: number
}