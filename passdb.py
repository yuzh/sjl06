# 2014.02.24 13:21:14 CST
#Embedded file name: passdb.py
#encoding=utf-8
import sys
import time
import os
import sqlite3
import json
import random
__all__ = ['passdb']
import ssh_util

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
        msg={'import data':x[2],'import date':time.ctime()}
        memo = json.dumps(msg)
        x = db.retrieve(user, host)
        if x:
            print ('Warning!', x)
        else:
            db.create(user, host, password, memo)

def gen_pass(PASSLEN):
    s0='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
    s1='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890'
    return random.choice(s0)+''.join(random.sample(s1,PASSLEN-1))

def check_args():
    if len(sys.argv)<2:
        return False
    l={'add':5,'gen':5,'get':4,'del':4,'set':6}.get(sys.argv[1])
    if not l or len(sys.argv)!=l:
        return False
    return True

def conn_host(user,host,passwd):
    try:
        ssh=ssh_util.ssh_util(host,22,user,passwd)
        return ssh
    except Exception as e:
        print('*** %s:Caught exception: %s: %s' % (host,e.__class__, e))
        return None

def set_passwd(user,host,passwd,newpass):
    try:
        ssh=ssh_util.ssh_util(host,22,user,passwd)
        ssh.passwd(user,newpass)
        return ssh
    except Exception as e:
        print('*** %s:Caught exception: %s: %s' % (host,e.__class__, e))
        return None

def add_host(db):
    host,user,oldpass=sys.argv[2:]
    msg={'add':time.ctime()}
    memo=json.dumps(msg)
    db.create(user,host,oldpass,memo)

def add_verify_host(db):
    host,user,oldpass=sys.argv[2:]
    ssh=conn_host(user,host,oldpass)
    if ssh:
        print('%s connect ok'%(host))
        #get more info by ssh.exec_command(),save to memos
        add_host(db)

def get_host(db):
    host,user=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        password,memo=rlt
        print('password is [%s]' % (password,))
        try:
            msg=json.loads(memo)
        except ValueError:
            msg={'old value':memo}
        print('--- memo ---')
        for k in msg.keys():
            print('%s => %s'%(k,msg[k]))
    else:
        print('host not found!')

def set_host(db):
    host,user,key,value=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        password,memo=rlt
        print('password is [%s]\nmemo is [%s]\n' % (password,memo))
        try:
            msg=json.loads(memo)
        except ValueError:
            msg={'old value':memo}
        msg[key]=value.decode('utf-8')
        memo=json.dumps(msg)
        db.update(user,host,password,memo)
    else:
        print('host not found!')

def gen_host_pass(db):
    host,user,oldpass=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        newpass=gen_pass(8)
        oldpass_indb,memo=rlt
        try:
            msg=json.loads(memo)
        except ValueError:
            msg={'old value':memo}
        msg['generate password']=time.ctime()
        memo=json.dumps(msg)
        db.update(user,host,newpass,memo)
        ssh=set_passwd(user,host,oldpass,newpass)
        if ssh:
            print('update %s password from %s to %s' % (host,oldpass,newpass) )
            db.conn.commit()
        else:
            print('update password fail!')
            db.conn.rollback()
    else:
        print('host not found!')

def del_host(db):
    host,user=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        password,memo=rlt
        rlt=raw_input('password is [%s]\nmemo is [%s]\nyes/no?' % (password,memo)).lower()
        if rlt in ('y','yes'):
            db.delete(user,host)
    else:
        print('host not found!')

def load_host(db):
    filename=sys.argv[2]
    ConvertTxtToDB(filename, db)

def main():
    usage="""Usage:
    %s add host user password
    %s gen host user oldpassword
    %s set host memo_type memo_data
    %s get host user
    %s del host user
    """ % ((sys.argv[0],)*5)
    if not check_args():
        print(usage)
        quit()
    func={'add':add_verify_host,'gen':gen_host_pass,'get':get_host,'del':del_host,\
        'load':load_host,'set':set_host}.get(sys.argv[1])
    db = passdb('pass.db')
    try:
        func(db)
        db.close()
    except sqlite3.DatabaseError,e:
        print `e`

if __name__ == '__main__':
    main()
