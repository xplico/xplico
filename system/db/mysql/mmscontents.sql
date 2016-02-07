--
-- Tabella dei contenuti degli mms
--
CREATE TABLE IF NOT EXISTS mmscontents (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  mm_id INTEGER,
  content_type VARCHAR( 255 ),
  filename VARCHAR( 255 ) DEFAULT 'No name',
  file_path VARCHAR( 255 ),
  file_size INTEGER,
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;
