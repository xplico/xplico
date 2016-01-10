--
-- Tabella dei gruppi degli utenti
--
CREATE TABLE IF NOT EXISTS groups (
  id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR( 40 ) NOT NULL UNIQUE
);

