import express from 'express'
import RSAUtils from './rsaUtils.js';
import { insertKey, getPairByPublic } from '../data/queries.js';
import { nanoid } from 'nanoid';

const router = express.Router()

router.post('/generate-keys', async (req, res) => {
  var keys = null
  try {
    keys = await RSAUtils.generateKeyPair();
    const pub= keys.publicKey
    insertKey.get(nanoid(), keys.publicKey,keys.privateKey, Date.now())
    res.json({ message: 'Keys generated successfully', pub });
  } catch (err) {
    res.status(500).json({ error: 'Error generating keys', details: err.message });
  }
});

// router.post('/generate-keys', async (req, res) => {
//   var keys = null
//   try {
//     keys = await RSAUtils.generateKeyPair();
//     const pub= keys.publicKey
//     const priv= keys.privateKey
//     insertKey.get(nanoid(), keys.publicKey,keys.privateKey, Date.now())
//     res.json({ message: 'Keys generated successfully', pub, priv});
//   } catch (err) {
//     res.status(500).json({ error: 'Error generating keys', details: err.message });
//   }
// });

router.post('/encrypt', (req, res) => {
  const { message, publicKey } = req.body
  try{
    const ciphertext = RSAUtils.encrypt(publicKey, message).toString("base64")
    res.json({ ciphertext})
  } catch (err) {
    res.status(500).json({ error: 'Error generating decrypt', details: err.message });
  }
})

router.post('/decrypt', (req, res) => {
    const { ciphertext , publicKey} = req.body
    const keys = getPairByPublic.get(publicKey)
    try {
      var output = RSAUtils.decrypt(keys.private_key, ciphertext).toString("utf8")
      res.json({ message: 'Decrypted successfully', output });
    } catch (err) {
      res.status(500).json({ error: 'Error generating decrypt', details: err.message });
    }
})

export default router