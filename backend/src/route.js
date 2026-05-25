import express from 'express'
import RSAUtils from './rsaUtils.js';
import { insertKey, getPairByPublic, getLatestKey, insertNonce } from '../data/queries.js';
import { nanoid } from 'nanoid';

const router = express.Router()

router.get('/public-key', (req, res) => {
  try{
    const keys = getLatestKey.get()
    res.json({public_key: keys.public_key});
  } catch (err) {
    res.status(500).json({error: 'Error obtaining latest key', details: err.message});
  }
})

router.post('/telemetry', (req, res) => {
  // const response = {}
  const {sensor_id, transmission_timestamp, encrypted_session_key, nonce, ciphertext, tag} = req.body;


  // checking id-nonce duplicate
  try{
    const insertNonceResult = insertNonce.run(sensor_id, nonce);
    console.log(insertNonceResult)
    // response.nonce_insertion = insertNonceResult
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      res.status(400).json({error: 'duplicate id-nonce pair' });
    }
    res.status(500).json({error: 'Error inserting nonce', details: err.message});
  }

  // decrypt session key
  let private_key;
  try{
    private_key = getLatestKey.get().private_key;
  } catch (err) {
    // console.error("Can't get latest private_key")
    res.status(500).json({error: "Can't get latest private_key", details: err.message});
  }
  // console.log(private_key)
  // console.log(encrypted_session_key)
  const session_key = RSAUtils.decrypt(private_key, encrypted_session_key)
  // console.log(session_key);
  // console.log(typeof session_key);
  // console.log(Buffer.isBuffer(session_key));
  res.json({ok: "ok"})
});

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