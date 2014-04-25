#encoding=utf-8
import sys
import time
import os
import sqlite3
import json
import traceback
__all__ = ['userdb']

class userdb:

    def __init__(self, dbname,autocommit=False):
        self.conn = sqlite3.connect(dbname)
        self.conn.row_factory = sqlite3.Row
        self.autocommit = autocommit

    def create(self, user = 'root', patt = '', date1 = None, date2 = None,memo = None):
        c = self.conn.cursor()
        sql = 'INSERT INTO users(username,pattern,date1,date2,memo) VALUES (?,?,?,?,?)'
        c.execute(sql, ( user, patt, date1, date2, memo))
        if self.autocommit:
            self.conn.commit()

    def retrieve(self, user = 'root'):
        c = self.conn.cursor()
        sql = 'SELECT userid,pattern,date1,date2,memo FROM users WHERE username=?'
        c.execute(sql, (user,))
        rlt = c.fetchall()
        return rlt

    def delete(self, user = 'root', userid  = -1):
        c = self.conn.cursor()
        sql = 'DELETE FROM users  WHERE username=? and userid=?'
        c.execute(sql, (user,userid))
        return c.rowcount
        if self.autocommit:
            self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()


def ConvertTxtToDB(txtfname, db):
    l = [ x.strip().split() for x in open(txtfname).readlines() if x[0] != '#' ]
    for x in l:
        user = x[0]
        pattern = x[1]
        try:
            date1=x[2]
        except IndexError as e:
            date1=None
        try:
            date2=x[3]
        except IndexError as e:
            date2=None
        memo = json.dumps({'loadtime':time.ctime()})
        db.create(user, pattern,date1,date2,memo)

def check_args():
    if len(sys.argv)<2:
        return False
    l={'add':6,'get':3,'del':4,'load':3}.get(sys.argv[1])
    if not l or len(sys.argv)!=l:
        return False
    return True

def add_user(db):
    username,pattern,date1,date2=sys.argv[2:]
    try:
        d1=time.strptime(date1,'%Y-%M-%d')
    except ValueError as e:
        print('date1 "%s" is invalid! format is yyyy-mm-dd'%(date1))
        return
    try:
        d2=time.strptime(date2,'%Y-%M-%d')
    except ValueError as e:
        print('date2 "%s" is invalid! format is yyyy-mm-dd'%(date2))
        return
    memo=json.dumps({
        'creator':os.getlogin(),
        'create_time':time.ctime()
    })
    db.create(username,pattern,date1,date2)

def get_user(db):
    user=sys.argv[2]
    rows=db.retrieve(user)
    for row in rows:
        line=','.join([x+':'+str(row[x]) for x in row.keys()])
        print(line)

def del_user(db):
    user,userid=sys.argv[2:]
    rowcount=db.delete(user,userid)
    print('delete %d rows'%rowcount)

def load_user(db):
    filename=sys.argv[2]
    ConvertTxtToDB(filename, db)

def main():
    usage="""Usage:
    %s add user pattern date1 date2
    %s get user
    %s del user id
    """ % (sys.argv[0],sys.argv[0],sys.argv[0])
    if not check_args():
        print(usage)
        quit()
    func={'add':add_user,'get':get_user,'del':del_user,\
        'load':load_user}.get(sys.argv[1])
    db = userdb('pass.db')
    try:
        func(db)
        db.close()
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()

if __name__ == '__main__':
    main()
