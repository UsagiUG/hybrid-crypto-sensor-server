import express from 'express'
import RSAUtils from './rsaUtils.js';
import AESUtils from './aesUtils.js';
import { insertKey, getPairByPublic, getLatestKey, insertNonce, getNonce, getSessionKey, insertSessionKey } from '../data/queries.js';
import { nanoid } from 'nanoid';

function invalidRequest(res){
  return res.status(400).json({error: 'invalid request'});
}

function serverError(res){
  return res.status(500).json({error: 'internal server error'});
}

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
  const {aad, nonce, ciphertext, tag} = req.body;
  const {sensor_id, transmission_timestamp, encrypted_session_key} = aad;
  console.log({aad: aad})
  
  // checking id-nonce duplicate
  try{
    const dupe_exists = getNonce.get(sensor_id, nonce);
    if (dupe_exists) {
      console.error("dupe id-nonce exists")
      return invalidRequest(res);
    }
  } catch(err) {
    console.error("Can't check id-nonce dupe", {details: err.message, time: new Date().toLocaleString("id-ID")})
    return serverError(res);
  }

  // checking if message is not expire
  let sent_time;
  const time_now = Date.now()
  const max_duration = 1000
  try{
    sent_time = new Date(transmission_timestamp).getTime();
    const transmission_duration = time_now - sent_time;
    if (transmission_duration > max_duration || transmission_duration < 0)
    {
      console.error("Expired message");
      return invalidRequest(res);
    }
  } catch(err) {
    console.error("Invalid date", {details: err.message});
    return invalidRequest(res);
  }

  // decrypt session key
  let private_key;
  let session_key;
  if (encrypted_session_key === null) {
    try{
      session_key = getSessionKey.get(sensor_id);
    } catch(err) {
      console.error("No previous session_key", {details: err.message});
      return invalidRequest(res);
    }
  } else {
    try{
      private_key = getLatestKey.get().private_key;
    } catch (err) {
      console.error("Can't get latest private_key", {details: err.message});
      return serverError(res);
    }
    try{
      session_key = RSAUtils.decrypt(private_key, encrypted_session_key)
    } catch (err) {
      console.error("Can't decrypt session key", {details: err.message});
      return invalidRequest(res);
    }
  }

  // decrypt message
  let decrypted_message
  try{
    decrypted_message = AESUtils.decrypt(session_key, req.body)
  } catch(err) {
    console.error("Can't decrypt with this session_key", {details: err.message});
    return invalidRequest(res);
  }

  // save nonce
  try{
    const insertNonceResult = insertNonce.run(sensor_id, nonce);
    console.log(insertNonceResult)
  } catch (err) {
    console.error({error: 'Error inserting nonce', details: err.message});
    return serverError(res);
  }

  // save session_key
  if (encrypted_session_key !== null) {
    try{
      const insertSessionKeyResult = insertSessionKey.run(sensor_id, session_key, sent_time);
      console.log(insertSessionKeyResult);
    } catch (err) {
      console.error("Cannot save session_key", {details: err.message});
      return serverError(res);
    }
  }

  console.log({decrypted_message: decrypted_message});
  res.json({decryption: "Success"});
});

router.post('/telemetry2', (req, res) => {
  // const response = {}
  const {aad, nonce, ciphertext, tag} = req.body;
  const {sensor_id, transmission_timestamp, encrypted_session_key} = JSON.parse(aad);
  // console.log("aad: ", aad);
  // console.log("aad (Buffer): ", Buffer.from(aad, 'base64'));

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
  // console.log(nonce);
  // console.log(typeof session_key);
  // console.log(Buffer.isBuffer(session_key));
  const decrypted_message = AESUtils.decrypt2(session_key, req.body)
  console.log(decrypted_message)
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