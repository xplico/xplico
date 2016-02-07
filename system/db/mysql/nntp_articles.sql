--
-- Tabella degli articoli del nntp
--
CREATE TABLE IF NOT EXISTS nntp_articles (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '1990-01-01 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '1990-01-01 00:00:00',
  nntp_group_id INTEGER NOT NULL REFERENCES nntp_groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  data_size INTEGER,
  first_visualization_user_id INTEGER NOT NULL DEFAULT  0,
  flow_info VARCHAR( 255 ) NOT NULL,
  receive BOOL DEFAULT FALSE,
  important BOOL DEFAULT FALSE,
  only_body BOOL DEFAULT FALSE,
  sender VARCHAR( 80 ),
  receivers VARCHAR( 1024 ),
  subject VARCHAR( 1024 ),
  mime_path VARCHAR( 255 ),
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;
