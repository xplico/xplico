--
-- Tabella delle tranzazioni web
--
CREATE TABLE IF NOT EXISTS webs (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  web_id INTEGER DEFAULT -1,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  first_visualization_user_id INTEGER COMMENT 'Id utente',
  flow_info VARCHAR( 255 ) NOT NULL COMMENT 'Xml file of flow',
  url VARCHAR( 4096 ),
  relation ENUM ('POSSIBLY_CONTAINER', 'POSSIBLY_CONTAINED', 'CONTAINER', 'CONTAINED', 'SERVICES', 'NONE') NOT NULL DEFAULT 'NONE',
  method VARCHAR( 10 ) NOT NULL,
  response VARCHAR( 5 ) NOT NULL,
  agent TEXT,
  host VARCHAR( 255 ) NOT NULL,
  content_type VARCHAR( 255 ) NOT NULL,
  rq_header VARCHAR( 255 ) COMMENT 'percorso del file',
  rq_body VARCHAR( 255 ) COMMENT 'percorso del file',
  rq_bd_size INTEGER,
  rs_header VARCHAR( 255 ) COMMENT 'percorso del file',
  rs_body VARCHAR( 255 ) COMMENT 'percorso del file',
  rs_bd_size INTEGER,
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;