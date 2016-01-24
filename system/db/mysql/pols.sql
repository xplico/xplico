--
-- Tabella dei punti di ascolto
--
CREATE TABLE IF NOT EXISTS pols (
  id INTEGER NOT NULL AUTO_INCREMENT,
  name VARCHAR( 40 ) NOT NULL COMMENT 'Nome del punto di ascolto',
  external_ref VARCHAR( 40 ) NULL COMMENT 'Riferimento esterno',
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  realtime BOOL DEFAULT FALSE,
  raw BOOL DEFAULT FALSE,
  PRIMARY KEY (id)
) TYPE = MYISAM ;

