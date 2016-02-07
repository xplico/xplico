--
-- Tabella delle webmail
--
CREATE TABLE IF NOT EXISTS webmails (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '1990-01-01 00:00:00',
  data_size INTEGER,
  first_visualization_user_id INTEGER NOT NULL DEFAULT 0,
  flow_info VARCHAR( 255 ) NOT NULL COMMENT 'Xml file of flow',
  receive BOOL DEFAULT FALSE,
  relevance INTEGER,
  service VARCHAR( 60 ),
  messageid VARCHAR( 256 ),
  sender VARCHAR( 80 ),
  receivers VARCHAR( 1024 ),
  cc_receivers VARCHAR( 1024 ),
  subject VARCHAR( 1024 ),
  mime_path VARCHAR( 255 ),
  txt_path VARCHAR( 255 ),
  html_path VARCHAR( 255 ),
  etype INTEGER,
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;
