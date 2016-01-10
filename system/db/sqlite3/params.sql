--
-- Tabella dei parametri
--
CREATE TABLE IF NOT EXISTS params (
  id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR( 40 ) NOT NULL UNIQUE,
  nvalue INTEGER,
  svalue VARCHAR( 80 )
);

