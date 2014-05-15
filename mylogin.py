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

DB_FILE=os.path.dirname(sys.argv[0])+'/pass.db'

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

def filter_rows(user_rows,host_rows):
    rlt = list()
    for user in user_rows:
        d=time.time()
        if d>=user['date1'] and d<=user['date2'] :
            p = re.compile(user['pattern'])
            h = [ x for x in host_rows if p.match('%s@%s'%(x['username'],x['hostname'])) ]
            rlt=rlt+h
    return rlt
    
def load_config(user,part_ip):
    db = userdb(DB_FILE)
    c = db.conn.cursor()
    sql='select username,pattern,strftime("%s",ifnull(date1,"1970-01-01"))+0 date1,'+\
        'strftime("%s",ifnull(date2,"2099-01-01"))+0 date2 from users WHERE username=?'
    c.execute(sql,(user,))
    user_rows = c.fetchall()
    sql = 'SELECT hostname,username,password FROM hosts WHERE hostname like "%s"'%(part_ip)
    c.execute(sql)
    host_rows = c.fetchall()
    db.close()
    return filter_rows(user_rows,host_rows)
   
def select_host(hosts):
    if len(hosts)==0:
        print(get_user()+':no hosts to connect!')
        return None
    t=[x['username']+'@'+x['hostname'] for x in hosts]
    p=pprint.PrettyPrinter(indent=4)
    p.pprint(list(enumerate(t)))
    t=raw_input('input index of host connect(quit/exit to quit):')
    try:
        i=int(t)
        return dict(enumerate(hosts))[i]
    except ValueError as e:
        if t.lower() not in ('exit','quit','q','x',''):
            print('invalid input "%s"'%(t))
    except KeyError as e:
        print('invalid index %s'%(t))

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

def ssh_host(username,hostname,password,port=22):
    try:
        s = struct.pack("HHHH", 0, 0, 0, 0)
        a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ , s))
    
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        print('*** Connecting...')
        client.connect(hostname, port, username, password)
        chan = client.invoke_shell('vt100',a[1],a[0])
        print(repr(client.get_transport()))
        print('*** Here we go!\n')
        logdir='/mnt/ssolog/%s/%s_%s/'%(get_user().replace('\\','/'),username,hostname)
        os.popen('mkdir -p '+logdir)
        logfile=time.strftime('%Y%m%d_%H%M%S',time.localtime())
        posix_shell(chan,logdir+logfile+'.log')
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
    if len(sys.argv)!=2:
        print('Usage:%s part_of_ip_address'%(sys.argv[0]))
        quit()
    rlt=load_config(get_user(),sys.argv[1])
    t=select_host(rlt)
    if t:
        ssh_host(t['username'],t['hostname'],t['password'])
    
if __name__=='__main__':
    main()
