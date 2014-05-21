#!/usr/bin/python
# 2014.02.24 13:21:14 CST
#Embedded file name: passdb.py
#encoding=utf-8
import sys
import time
import os
import sqlite3
import json
import random
import traceback
__all__ = ['passdb']
import ssh_util
import logdb

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
    l={'add':5,'gen':5,'get':4,'del':4,'set':6,'load':3,'zbx':4}.get(sys.argv[1])
    if not l or len(sys.argv)!=l:
        return False
    return True

def conn_host(user,host,passwd):
    try:
        ssh=ssh_util.ssh_util(host,22,user,passwd)
        return ssh
    except Exception as e:
        print('*** %s:conn_host: %s: %s' % (host,e.__class__, e))
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
    return 'add ok'

def add_verify_host(db):
    host,user,oldpass=sys.argv[2:]
    ssh=conn_host(user,host,oldpass)
    if ssh:
        print('%s connect ok'%(host))
        #get more info by ssh.exec_command(),save to memos
        return add_host(db)
    else:
        return 'connect fail'

def get_host(db):
    host,user=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        password,memo=rlt
        try:
            msg=json.loads(memo)
        except ValueError:
            msg={'old value':memo}
        print('--- memo ---')
        for k in msg.keys():
            print('%s => %s'%(k,msg[k]))
        ret='get memo'
        t=raw_input('input name:')
        if t==os.getlogin():
            print('password is [%s]' % (password,))
            ret=ret+',password'
        return ret+',ok'
    else:
        print('host not found!')
        return 'host not found!'

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
        return 'set info ok'
    else:
        print('host not found!')
        return 'host not found!'

def gen_host_pass(db):
    host,user,oldpass=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        if os.environ.get('MANUAL_PASSWORD'):
            newpass=raw_input('input password:')
        else:
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
            return 'update password ok'
        else:
            print('update password fail!')
            db.conn.rollback()
            return 'update password fail!'
    else:
        print('host not found!')
        return 'host not found!'

def del_host(db):
    host,user=sys.argv[2:]
    rlt=db.retrieve(user,host)
    if rlt:
        password,memo=rlt
        rlt=raw_input('password is [%s]\nmemo is [%s]\nyes/no?' % (password,memo)).lower()
        if rlt in ('y','yes'):
            db.delete(user,host)
            return 'del host ok'
    else:
        print('host not found!')
        return 'host not found!'

def load_host(db):
    filename=sys.argv[2]
    ConvertTxtToDB(filename, db)

def zbx_run(db):
    host,cmd=sys.argv[2:]
    rlt=db.retrieve('root',host)
    if rlt:
        password,memo=rlt
        try:
            zbx=ssh_util.zbx_util(host,22,'root',password)
            ret=zbx.execute(cmd)
            for k in ret.keys():
                print('[%s]:%s'%(k,ret[k]))
            return cmd+',ok'
        except Exception as e:
            print '*** zbx_run: %s: %s' % (e.__class__, e)
            traceback.print_exc()
            return '*** zbx_run: %s: %s' % (e.__class__, e)
    else:
        print('host not found!')
        return 'host not found!'

    return 'add ok'
def main():
    usage="""Usage:
    %s add host user password
    %s gen host user oldpassword
    %s set host user memo_type memo_data
    %s get host user
    %s del host user
    %s zbx host <status|start|stop|reg|unreg|install|remove>
    """ % ((sys.argv[0],)*6)
    if not check_args():
        print(usage)
        quit()
    func={'add':add_verify_host,'gen':gen_host_pass,'get':get_host,'del':del_host,\
        'load':load_host,'set':set_host,'zbx':zbx_run}.get(sys.argv[1])
    db = passdb(os.path.dirname(sys.argv[0])+'/pass.db')
    log = logdb.logdb(os.path.dirname(sys.argv[0])+'/logs.db',True)
    try:
        rlt=func(db)
        db.close()
    except Exception as e:
        print('*** func: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        rlt='*** func: %s: %s' % (e.__class__, e)
    log.create2(' '.join(sys.argv),rlt)

if __name__ == '__main__':
    main()
