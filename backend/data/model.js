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
  id    INTEGER NOT NULL, 
  nonce TEXT NOT NULL,
  UNIQUE(id, nonce)
  );
`;
database.exec(initRsaKeysTable);
database.exec(initNonceTable)

export default database;