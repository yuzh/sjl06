# 2014.02.24 13:21:14 CST
#Embedded file name: passdb.py
#encoding=utf-8
import sys
import time
import os
import sqlite3
__all__ = ['passdb']

class passdb:

    def __init__(self, dbname,autocommit=False):
        self.conn = sqlite3.connect(dbname)
        self.autocommit = autocommit

    def create(self, user = 'root', host = 'localhost', password = '', memo = ''):
        c = self.conn.cursor()
        sql = 'INSERT INTO hosts(hostname,username,password,memo) VALUES (?,?,?,?)'
        c.execute(sql, ( host, user, password, memo))
        if self.autocommit:
            self.conn.commit()

    def retrieve(self, user = 'root', host = 'localhost'):
        c = self.conn.cursor()
        sql = 'SELECT password,memo FROM hosts WHERE hostname=? and username=?'
        c.execute(sql, (host,user))
        rlt = c.fetchone()
        return rlt

    def update(self, user = 'root', host = 'localhost', password = '', memo = ''):
        c = self.conn.cursor()
        sql = 'UPDATE hosts SET password=?,memo=? WHERE hostname=? and username=?'
        c.execute(sql, (password, memo, host, user))
        if self.autocommit:
            self.conn.commit()

    def delete(self, user = 'root', host = 'localhost'):
        c = self.conn.cursor()
        sql = 'DELETE FROM hosts  WHERE hostname=? and username=?'
        c.execute(sql, (host,user))
        if self.autocommit:
            self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()


def ConvertTxtToDB(txtfname, db):
    l = [ x.strip().split() for x in open(txtfname).readlines() if x[0] != '#' ]
    for x in l:
        user, host = x[0].split('@')
        password = x[1]
        memo = x[2]
        x = db.retrieve(user, host)
        if x:
            print ('Warning!', x)
        else:
            db.create(user, host, password, memo)

def check_args():
    if len(sys.argv)<2:
        return False
    l={'add':5,'update':5,'get':4,'del':4}.get(sys.argv[1])
    if not l or len(sys.argv)!=l:
        return False
    return True

def add_host(db):
    host,user,oldpass=sys.argv[2:]
    db.create(user,host,oldpass,'add '+time.ctime())

def get_host(db):
    host,user=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        password,memo=rlt
        print('password is [%s]\nmemo is [%s]\n' % (password,memo))
    else:
        print('host not found!')

def update_host(db):
    host,user,oldpass=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        db.update(user,host,oldpass,'update '+time.ctime())
    else:
        print('host not found!')

def del_host(db):
    host,user=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        db.delete(user,host)
    else:
        print('host not found!')

def load_host(db):
    filename=sys.argv[2]
    ConvertTxtToDB(filename, db)

def main():
    usage="""Usage:
    %s add host user old_pass
    %s update host user old_pass
    %s get host user
    %s del host user
    """ % (sys.argv[0],sys.argv[0],sys.argv[0],sys.argv[0])
    if not check_args():
        print(usage)
        quit()
    func={'add':add_host,'update':update_host,'get':get_host,'del':del_host,\
        'load':load_host}.get(sys.argv[1])
    db = passdb('pass.db')
    try:
        func(db)
        db.close()
    except sqlite3.DatabaseError,e:
        print `e`

if __name__ == '__main__':
    main()
