import express from 'express'
import router from './src/route.js'
import config from './src/config.js'
import {getLatestKey, insertKey} from './data/queries.js'
import RSAUtils from './src/rsaUtils.js'
import { nanoid } from 'nanoid'

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(router)
app.listen(3000, async () => {
  console.log('Server is running on port 3000')

  try{
    const existing = getLatestKey.get()
    if (!existing) {
      const keys = await RSAUtils.generateKeyPair()
      insertKey.run(nanoid(), keys.publicKey, keys.privateKey, Date.now())
      console.log('RSA keys generated successfully')
    } else {
      console.log('RSA keys already exist')
      // console.log(getLatestKey.get().public_key)
    }
  } catch (err) {
    console.error('Error generating RSA keys', err.message)
  }
})