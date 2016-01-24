--
-- Tabella degli utenti
--
CREATE TABLE IF NOT EXISTS users (
  id INTEGER NOT NULL AUTO_INCREMENT,
  username VARCHAR( 40 ) NOT NULL,
  password VARCHAR( 40 ) NOT NULL,
  email VARCHAR( 255 ) NOT NULL,
  em_checked BOOL DEFAULT 0 COMMENT 'Stato verifica e.mail ',
  em_key VARCHAR( 40 ) NOT NULL COMMENT 'Chiave di verifica e.mail',
  first_name VARCHAR( 40 ) NOT NULL,
  last_name VARCHAR( 40 ) NOT NULL,
  last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  login_num INTEGER NOT NULL DEFAULT 0,
  user_type ENUM('NORMAL','GRP_ADMIN','SYSTEM_ADMIN') DEFAULT 'NORMAL',
  enabled BOOLEAN DEFAULT TRUE,
  accept_notes BOOLEAN DEFAULT TRUE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  quota_used INTEGER,
  PRIMARY KEY (id),
  UNIQUE KEY username (username),
  UNIQUE KEY email (email)
) TYPE = MYISAM ;
