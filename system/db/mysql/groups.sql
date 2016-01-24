--
-- Tabella dei gruppi degli utenti
--
CREATE TABLE IF NOT EXISTS groups (
  id INTEGER NOT NULL AUTO_INCREMENT,
  name VARCHAR( 40 ) NOT NULL COMMENT 'Nome del gruppo',
  PRIMARY KEY (id),
  UNIQUE KEY name (name)
) TYPE = MYISAM ;

