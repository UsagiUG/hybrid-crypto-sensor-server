import express from 'express'
import router from './src/route.js'
import config from './src/config.js'
import {getLatestKey, insertKey} from './data/queries.js'
import RSAUtils from './src/rsaUtils.js'
import { nanoid } from 'nanoid'

const app = express()

app.use(express.json({ limit: '200kb' }));
app.use(router)
app.listen(3000, async () => {
  console.log('Server is running on port 3000')
})