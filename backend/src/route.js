import express from 'express';
import RSAUtils from './rsaUtils.js';
import AESUtils from './aesUtils.js';
import { insertKey, getPairByPublic, getLatestKey, insertNonce, getNonce, getSessionKey, insertSessionKey } from '../data/queries.js';
import { nanoid } from 'nanoid';
import ECCUtils from './eccUtils.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const thisFilePath = path.dirname(fileURLToPath(import.meta.url));
const rsaPrivateKeyPath = path.resolve(thisFilePath, '../certs/rsa_private_key.pem');
const eccPrivateKeyPath = path.resolve(thisFilePath, '../certs/ecc_private_key.pem');

let rsaPrivateKey;
try{
  rsaPrivateKey = fs.readFileSync(rsaPrivateKeyPath, 'utf-8');
  console.log('RSA private key successfully loaded');
} catch(err){
  console.error('RSA private key failed to load', {cause: err});
}

let eccPrivateKey;
try{
  eccPrivateKey = fs.readFileSync(eccPrivateKeyPath, 'utf-8');
  console.log('ECC private key successfully loaded');
} catch(err){
  console.error('ECC private key failed to load', {cause: err});
}

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
    res.status(500).json({error: 'Error obtaining latest key', cause: err.message});
  }
})

function decryption(req) {
  const {aad, nonce, ciphertext, tag} = req.body;
  const {sensor_id, mode, transmission_timestamp, key} = aad;
  let sessionKey;
  if(mode === 'rsa') {
    try{
      console.log({rsaPrivateKey: rsaPrivateKey});
      sessionKey = RSAUtils.decrypt(rsaPrivateKey, key);
    } catch(err) {
      throw new Error("Can't decrypt encrypted session key with RSA private key", {cause: err});
    }
  } else {
    try {
      sessionKey = ECCUtils.decrypt(eccPrivateKey, key);
    } catch(err) {
      throw new Error("Can't compute session key with provided server's ECC private key and client's ECC ephemeral public key", {cause: err});
    }
  }

  let decryptedMessage;
  // console.log({sessionKey: sessionKey, req: req.body});
  try {
    decryptedMessage = AESUtils.decrypt(sessionKey, req.body);
  } catch(err) {
    throw new Error("Can't decrypt ciphertext or verify tag", {cause: err});
  }

  return decryptedMessage;
}

// function rsa(req, res) {
//   const {aad, nonce, ciphertext, tag} = req.body;
//   const {sensor_id, mode, transmission_timestamp, key} = aad;
//   let private_key;
//   let session_key;
//     try{
//       private_key = rsaPrivateKey;
//     } catch (err) {
//       console.error("Can't get latest private_key", {details: err.message});
//       return serverError(res);
//     }
//     try{
//       session_key = RSAUtils.decrypt(private_key, key)
//     } catch (err) {
//       console.error("Can't decrypt session key", {details: err.message});
//       return invalidRequest(res);
//     }

//   // decrypt message
//   let decrypted_message;
//   try{
//     decrypted_message = AESUtils.decrypt(session_key, req.body)
//   } catch(err) {
//     throw new Error("Can't decrypt with this session_key", {details: err});
//     return invalidRequest(res);
//   }

//   return decrypted_message;
// }

// function ecc(req, res) {
//   const {aad, nonce, ciphertext, tag} = req.body;
//   const {sensor_id, mode, transmission_timestamp, key} = aad;
//   let private_key;
//   let session_key;
//     try{
//       private_key = eccPrivateKey;
//     } catch (err) {
//       throw new Error("Can't get latest private_key", {details: err});
//       return serverError(res);
//     }
//     try{
//       session_key = ECCUtils.decrypt(private_key, key)
//     } catch (err) {
//       throw new Error("Can't decrypt session key", {details: err});
//       return invalidRequest(res);
//     }

//   // decrypt message
//   let decrypted_message;
//   decrypted_message = AESUtils.decrypt(session_key, req.body)
//   if (!decrypted_message) {
//     return;
//   }

//   return decrypted_message;
// }

const durations = [];

router.post('/telemetry', (req, res) => {
  const start = performance.now();
  const {aad, nonce, ciphertext, tag} = req.body;
  const {sensor_id, mode, transmission_timestamp, key} = aad;
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

  let decryptedMessage;
  try {
    decryptedMessage = decryption(req);
  } catch(err) {
    invalidRequest(res)
    return console.log(err)
  }
  // if (mode === 'rsa') {
  //   try {
  //     decrypted_message = rsa(req, res)
  //   } catch(err) {
  //     console.error("error rsa", {details: err.message});
  //     return serverError(res);
  //   }
  // } else {
  //   try {
  //     decrypted_message = ecc(req, res)
  //   } catch(err) {
  //     console.error("error ecc", {details: err.message});
  //     return serverError(res);
  //   }
  // }
  const end = performance.now();
  durations.push(end - start);
  
  // save nonce
  try{
    const insertNonceResult = insertNonce.run(sensor_id, nonce);
    console.log(insertNonceResult)
  } catch (err) {
    console.error({error: 'Error inserting nonce', details: err.message});
    return serverError(res);
  }

  // save session_key
  // if (encrypted_session_key !== null) {
  //   try{
  //     const insertSessionKeyResult = insertSessionKey.run(sensor_id, session_key, sent_time);
  //     console.log(insertSessionKeyResult);
  //   } catch (err) {
  //     console.error("Cannot save session_key", {details: err.message});
  //     return serverError(res);
  //   }
  // }

  console.log({time: new Date().toLocaleString("id-ID"), decryptedMessage: decryptedMessage});

  // if (durations.length % 30 === 0) {
  //     const mean = durations.reduce((a, b) => a + b) / durations.length;
  //     const sorted = [...durations].sort((a, b) => a - b);
  //     const median = sorted[Math.floor(sorted.length / 2)];
  //     const std = Math.sqrt(durations.reduce((a, b) => a + (b - mean) ** 2, 0) / durations.length);
  //     console.log(durations.join(','));
  //     console.log(`n=${durations.length} | mean=${mean.toFixed(3)}ms | median=${median.toFixed(3)}ms | std=${std.toFixed(3)}ms`);
  //   }  
  
  res.json({decryption_duration: end-start});
});

// router.post('/telemetry2', (req, res) => {
//   // const response = {}
//   const {aad, nonce, ciphertext, tag} = req.body;
//   const {sensor_id, transmission_timestamp, key} = JSON.parse(aad);
//   // console.log("aad: ", aad);
//   // console.log("aad (Buffer): ", Buffer.from(aad, 'base64'));

//   // checking id-nonce duplicate
//   try{
//     const insertNonceResult = insertNonce.run(sensor_id, nonce);
//     console.log(insertNonceResult)
//     // response.nonce_insertion = insertNonceResult
//   } catch (err) {
//     if (err.message.includes('UNIQUE constraint failed')) {
//       res.status(400).json({error: 'duplicate id-nonce pair' });
//     }
//     res.status(500).json({error: 'Error inserting nonce', details: err.message});
//   }

//   // decrypt session key
//   let private_key;
//   try{
//     private_key = getLatestKey.get().private_key;
//   } catch (err) {
//     // console.error("Can't get latest private_key")
//     res.status(500).json({error: "Can't get latest private_key", details: err.message});
//   }
//   // console.log(private_key)
//   // console.log(encrypted_session_key)
//   const session_key = RSAUtils.decrypt(private_key, encrypted_session_key)
//   // console.log(nonce);
//   // console.log(typeof session_key);
//   // console.log(Buffer.isBuffer(session_key));
//   const decrypted_message = AESUtils.decrypt2(session_key, req.body)
//   console.log(decrypted_message)
//   res.json({ok: "ok"})
// });



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