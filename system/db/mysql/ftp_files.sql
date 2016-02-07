--
-- Tabella dei file estratti da ftp-data
--
CREATE TABLE IF NOT EXISTS ftp_files (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  ftp_id INTEGER,
  first_visualization_user_id INTEGER,
  flow_info VARCHAR( 255 ) NOT NULL,
  filename VARCHAR( 255 ),
  file_path VARCHAR( 255 ),
  file_size INTEGER,
  file_percentual INTEGER DEFAULT 100,
  info_part VARCHAR( 255 ),
  dowloaded INTEGER,
  hole INTEGER DEFAULT 0,
  complete INTEGER DEFAULT 1,
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
  FOREIGN KEY (ftp_id) REFERENCES ftps(id) ON DELETE CASCADE
) TYPE = MYISAM ;