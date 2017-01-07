--- clean all tables except users and groups

PRAGMA foreign_keys = ON;
DELETE FROM pols;
DELETE FROM sols;
UPDATE users SET quota_used=0;
UPDATE params SET nvalue=1 WHERE name="register";

