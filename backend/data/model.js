import { DatabaseSync } from 'node:sqlite';

const database = new DatabaseSync(`${import.meta.dirname}/main.db`);

const initRsaKeysTable = `
CREATE TABLE IF NOT EXISTS keys (
  key_id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

const initNonceTable = `
  CREATE TABLE IF NOT EXISTS nonces(
  sensor_id    INTEGER NOT NULL, 
  nonce TEXT NOT NULL,
  UNIQUE(sensor_id, nonce)
  );
`;

const initSessionKeysTable = `
  CREATE TABLE IF NOT EXISTS session_keys(
  sensor_id     INTEGER NOT NULL,
  session_key   TEXT NOT NULL,
  created_at    INTEGER NOT NULL
  );
`;

database.exec(initRsaKeysTable);
database.exec(initNonceTable);
database.exec(initSessionKeysTable);

export default database;