--
-- Tabella dei punti di ascolto
--
CREATE TABLE IF NOT EXISTS pols (
  id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR( 40 ) NOT NULL,
  external_ref VARCHAR( 40 ) NULL,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  realtime BOOL DEFAULT 0,
  raw BOOL DEFAULT 0
);

