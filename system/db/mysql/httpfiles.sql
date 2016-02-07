--
-- Tabella dei file scaricati on HTTP
--
CREATE TABLE IF NOT EXISTS httpfiles (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  first_visualization_user_id INTEGER NOT NULL DEFAULT 0,
  flow_info VARCHAR( 255 ) NOT NULL COMMENT 'Xml file of flow',
  important BOOL DEFAULT FALSE,
  url VARCHAR( 4096 ),
  content_type VARCHAR( 255 ) DEFAULT '',
  file_path VARCHAR( 255 ),
  file_name VARCHAR( 1024 ),
  file_size INTEGER,
  file_parts VARCHAR( 255 ),
  file_stat VARCHAR( 25 ),
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;
