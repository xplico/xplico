--
-- Tabella delle tranzazioni web
--
CREATE TABLE IF NOT EXISTS webs (
  id INTEGER NOT NULL PRIMARY KEY,
  sol_id INTEGER NOT NULL REFERENCES sols(id) ON DELETE CASCADE ON UPDATE CASCADE,
  pol_id INTEGER NOT NULL REFERENCES pols(id) ON DELETE CASCADE ON UPDATE CASCADE,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE ON UPDATE CASCADE,
  web_id INTEGER DEFAULT -1,
  capture_date TIMESTAMP NOT NULL DEFAULT '1990-01-01 00:00:00',
  decoding_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_date TIMESTAMP NOT NULL DEFAULT '1990-01-01 00:00:00',
  first_visualization_user_id INTEGER,
  flow_info VARCHAR( 255 ) NOT NULL,
  url VARCHAR( 4096 ),
  relation VARCHAR( 40 ) DEFAULT 'NONE',
  method VARCHAR( 10 ) NOT NULL,
  response VARCHAR( 5 ) NOT NULL,
  agent TEXT,
  host VARCHAR( 255 ) NOT NULL,
  content_type VARCHAR( 255 ) NOT NULL,
  rq_header VARCHAR( 255 ),
  rq_body VARCHAR( 255 ),
  rq_bd_size INTEGER,
  rs_header VARCHAR( 255 ),
  rs_body VARCHAR( 255 ),
  rs_bd_size INTEGER
);
