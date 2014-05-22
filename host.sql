PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE hosts (
  hostid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  hostname varchar(64) NOT NULL,
  username varchar(64) NOT NULL,
  password varchar(64) default NULL,
  memo text default NULL
);
CREATE UNIQUE INDEX idx_entry on hosts(hostname,username);
COMMIT;
