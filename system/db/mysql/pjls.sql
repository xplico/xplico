--
-- Tabella delle stampe eseguite con pjl
--
CREATE TABLE IF NOT EXISTS pjls (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  first_visualization_user_id INTEGER,
  flow_info VARCHAR( 255 ) NOT NULL,
  url VARCHAR( 255 ),
  pdf_path VARCHAR( 255 ),
  pdf_size INTEGER,
  pcl_path VARCHAR( 255 ),
  pcl_size INTEGER,
  error INTEGER DEFAULT 0,
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;