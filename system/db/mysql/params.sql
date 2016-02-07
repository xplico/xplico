--
-- Tabella dei parametri
--
CREATE TABLE IF NOT EXISTS params (
  id INTEGER NOT NULL AUTO_INCREMENT,
  name VARCHAR( 40 ) NOT NULL COMMENT 'Param name',
  nvalue INTEGER,
  svalue VARCHAR( 80 ),
  PRIMARY KEY (id),
  UNIQUE KEY name (name)
) TYPE = MYISAM ;

