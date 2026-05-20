// data/queries.js
import database from './model.js';

const insertKey = database.prepare(`
  INSERT INTO keys (key_id, public_key, private_key, created_at)
  VALUES (?, ?, ?, ?)
`);

const getPairByPublic = database.prepare(`
  SELECT * FROM keys WHERE public_key = (?)
`);

const getPairByPrivate = database.prepare(`
  SELECT * FROM keys WHERE private_key = (?)
`);

const getLatestKey = database.prepare(`
  SELECT * FROM keys ORDER BY created_at DESC LIMIT 1
`);

export {
  insertKey,
  getPairByPrivate,
  getPairByPublic,
  getLatestKey
};