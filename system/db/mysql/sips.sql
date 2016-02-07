--
-- Tabella delle chiamate sip
--
CREATE TABLE IF NOT EXISTS sips (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  data_size INTEGER COMMENT 'Dimensioni in Kb',
  first_visualization_user_id INTEGER NOT NULL DEFAULT 0 COMMENT 'Id utente',
  flow_info VARCHAR( 255 ) NOT NULL COMMENT 'XML file of flow',
  commands VARCHAR( 80 ),
  from_addr VARCHAR( 80 ),
  to_addr VARCHAR( 1024 ),
  ucaller VARCHAR( 255 ),
  ucalled VARCHAR( 255 ),
  umix VARCHAR( 255 ),
  duration INTEGER,
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;