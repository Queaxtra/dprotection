import express from 'express'
import { secure, protect, limit } from './src/protection/middleware'
import { Guard } from './src/protection/services/protection.service'

const app = express()

app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))

app.use(secure)
app.use(limit)
app.use(protect)

Guard.config({
  routes: {
    '/api': { limit: 50, window: 60000 },
    '/login': { limit: 10, window: 60000 }
  },
  burst: 10,
  time: 1000,
  score: 2.5
})

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/api', (req, res) => {
  res.json({ 
    message: 'API endpoint', 
    query: req.query 
  })
})

app.post('/api', (req, res) => {
  res.json({ 
    message: 'API POST endpoint', 
    body: req.body 
  })
})

app.get('/login', (req, res) => {
  res.json({ message: 'Login page' })
})

app.post('/login', (req, res) => {
  res.json({ 
    message: 'Login endpoint',
    body: req.body
  })
})

app.post('/test', (req, res) => {
  res.json({ message: 'Test endpoint successful', body: req.body })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})