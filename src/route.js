import express from 'express'
import RSAUtils from './rsaUtils.js';
const router = express.Router()

router.post('/generate-keys', async (req, res) => {
  var keys = null
  try {
    keys = await RSAUtils.generateKeyPair();
    res.json({ message: 'Keys generated successfully', keys });
  } catch (err) {
    res.status(500).json({ error: 'Error generating keys', details: err.message });
  }
});

router.post('/encrypt', (req, res) => {
  const { message, publicKey } = req.body
  const ciphertext = RSAUtils.encrypt(publicKey, message).toString("base64")
  res.json({ ciphertext})
})

router.post('/decrypt', (req, res) => {
    const { ciphertext , privateKey} = req.body
    try {
      var output = RSAUtils.decrypt(privateKey, ciphertext).toString("utf8")
      res.json({ message: 'Decrypted successfully', output });
    } catch (err) {
      res.status(500).json({ error: 'Error generating decrypt', details: err.message });
    }
})

export default router