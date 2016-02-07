--
-- Tabella dei canali della chat palalk
--
CREATE TABLE IF NOT EXISTS paltalk_rooms (
  id INTEGER NOT NULL AUTO_INCREMENT,
  sol_id INTEGER NOT NULL,
  pol_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  capture_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  first_visualization_user_id INTEGER DEFAULT 0,
  flow_info VARCHAR( 255 ) NOT NULL COMMENT 'Xml file of flow',
  room VARCHAR( 255 ),
  end_date TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  room_path VARCHAR( 255 ),
  duration VARCHAR( 255 ),
  rusers VARCHAR( 255 ),
  rnick VARCHAR( 255 ),
  PRIMARY KEY (id),
  FOREIGN KEY (pol_id) REFERENCES pols(id) ON DELETE CASCADE,
  FOREIGN KEY (sol_id) REFERENCES sols(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
) TYPE = MYISAM ;
