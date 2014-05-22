PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE oplog (
  logid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  logname varchar(64) NOT NULL,
  logtime varchar(64) NOT NULL,
  memo text default NULL
);
CREATE UNIQUE INDEX idx_log on oplog(logname,logtime);
COMMIT;
