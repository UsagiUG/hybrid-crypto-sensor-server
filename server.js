import express from 'express'
import router from './src/route.js'
import config from './src/config.js'
const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(router)
app.listen(3000, () => {
  console.log('Server is running on port 3000')
})