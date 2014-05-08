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
from userdb import userdb
from passwd import passdb

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

def filter_rows(user_rows,host_rows):
    
def load_config(user,part_ip):
   db = userdb(DB_FILE)
   c = db.conn.cursor()
   sql = 'SELECT userid,pattern,date1,date2,memo FROM users WHERE username=?'
   c.execute(sql,(user,))
   user_rows = c.fetchall()
   sql = 'select hostname,username,password from hosts where instr(hostname,"%s")'%(part_ip)
   c.execute(sql)
   host_rows = c.fetchall()
   db.close()
   return filter_rows(user_rows,host_rows)
   

def main():
    
if __name__=='__main__':
    main()
