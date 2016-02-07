--
-- Tabella delle transazioni nntp dei gruppi
--
CREATE TABLE IF NOT EXISTS nntp_groups (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  name VARCHAR( 1024 ),
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;
