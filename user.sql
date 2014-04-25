PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
  userid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  username varchar(64) NOT NULL,
  pattern  varchar(64) NOT NULL,
  date1    varchar(64) default NULL,
  date2    varchar(64) default NULL,
  memo     text default NULL
);
CREATE INDEX idx_users on users(username);
COMMIT;
