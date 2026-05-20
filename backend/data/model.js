import { DatabaseSync } from 'node:sqlite';

const database = new DatabaseSync(`${import.meta.dirname}/main.db`);

const initDatabase = `
CREATE TABLE IF NOT EXISTS keys (
  key_id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

database.exec(initDatabase);

export default database;