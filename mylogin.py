#!/usr/bin/python
#encoding=utf-8
import os
import sys
import string
import re
import time
import sqlite3
import json
import traceback
import paramiko
import pprint
import struct
import fcntl
import termios
import tty

from userdb import userdb

DB_FILE='pass.db'

LOG_DIR='/mnt/ssolog/'+os.getlogin().replace('\\','_')+os.sep

def do_login(host,username,password,logfname):
    cmd='ssh -i /root/spdblogin/id_spdb %s@%s' % (username,host)
    child=pexpect.spawn(cmd,logfile=open(logfname,'w'))
    try:
        child.interact(output_filter=myOutFilter)
        #child.interact()
    except OSError:
        pass
    except: 
        print "Unexpected error:", sys.exc_info()[0:2]
    child.close()


def set_title(title):
    print('\x1b]0;'+title+'\x07')

def show_help():
    print('usage:%s part_of_ip_addr' % (sys.argv[0]) )
    quit()

def get_user():
    if os.getuid()==0:
        return os.getenv('USER')
    else:
        return os.getlogin()
def ParseDate(tval):
    support_formats=( '%Y/%m/%d','%Y%m%d', '%Y/%m/%d-%H:%M:%S',  '%Y-%m-%d', '%Y%m%d%H%M%S')
    for f in support_formats:
        try:
            tmp=time.strptime(tval,f)
            #print('debug:match',tval,f)
            return time.mktime(tmp)
        except ValueError,e:
            print('Invalid date/time value:',tval)
            print('Valid date/time values are:'+','.join(map(time.strftime,support_formats)))
    return time.time()

def filter_rows(user_rows,host_rows):
    rlt = list()
    #print('DEBUG user',user_rows)
    #print('DEBUG host',host_rows)
    for user in user_rows:
        if user['date1']:
            d1=ParseDate(d1)
        else:
            d1=0
        if user['date2']:
            d2=ParseDate(d2)
        else:
            d2=ParseDate('2030/12/31')
        d=time.time()
        if d>=d1 and d<=d2 :
            p = re.compile(user['pattern'])
            h = [ x for x in host_rows if p.match('%s@%s'%(x['username'],x['hostname'])) ]
            rlt=rlt+h
    return rlt
    
def load_config(user,part_ip):
    db = userdb(DB_FILE)
    c = db.conn.cursor()
    sql = 'SELECT userid,pattern,date1,date2,memo FROM users WHERE username=? '
    c.execute(sql,(user,))
    user_rows = c.fetchall()
    sql = 'SELECT hostname,username,password FROM hosts WHERE instr(hostname,"%s")'%(part_ip)
    c.execute(sql)
    host_rows = c.fetchall()
    db.close()
    return filter_rows(user_rows,host_rows)
   
def select_host(hosts):
    if len(hosts)==0:
        print('None hosts to slect!')
        return None
    t=[x['username']+'@'+x['hostname'] for x in hosts]
    p=pprint.PrettyPrinter(indent=4)
    p.pprint(list(enumerate(t)))
    t=raw_input('select index(quit/exit to quit):')
    try:
        i=int(t)
        return dict(enumerate(hosts))[i]
    except ValueError as e:
        if t.lower() not in ('exit','quit'):
            print('invalid input "%s"'%(t))
    except KeyError as e:
        print('invalid index "%s"'%(t))

def posix_shell(chan,logfile):
    import select
    
    oldtty = termios.tcgetattr(sys.stdin)
    f=open(logfile,'w')
    try:
        mode = tty.tcgetattr(sys.stdin.fileno())
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

        while True:
            r, w, e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    #x = u(chan.recv(1024))
                    x = chan.recv(1024)
                    if len(x) == 0:
                        sys.stdout.write('\r\n*** EOF\r\n')
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                    f.write(x)
                    f.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                #x = sys.stdin.read(1)
                x=os.read(sys.stdin.fileno(),1000)
                if len(x) == 0:
                    break
                chan.send(x)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
        f.close()

def ssh_host(username,hostname,password):
    try:
        s = struct.pack("HHHH", 0, 0, 0, 0)
        a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ , s))
    
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        print('*** Connecting...')
        port=22
        client.connect(hostname, port, username, password)
        chan = client.invoke_shell('vt100',a[1],a[0])
        print(repr(client.get_transport()))
        print('*** Here we go!\n')
        posix_shell(chan,'/tmp/'+hostname+'_trace.log')
        chan.close()
        client.close()
    
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        try:
            client.close()
        except:
            pass
        sys.exit(1)

def main():
    rlt=load_config(sys.argv[1],sys.argv[2])
    t=select_host(rlt)
    if t:
        ssh_host(t['username'],t['hostname'],t['password'])
    
if __name__=='__main__':
    main()
