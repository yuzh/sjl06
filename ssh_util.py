#encoding=utf-8
import sys
import time
import os
import paramiko
import traceback
__all__ = ['ssh_util']

class ssh_util:

    def __init__(self, hostname,port,username,password):
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.client.connect(hostname,port,username,password)
        self.hostname=hostname
        self.os_type=self.get_os_type()

    def passwd(self,username,password):
        # special for hpux trust mode
        stdin,stdout,stderr=self.client.exec_command('ls /tcb')
        trust_convert=False
        if len(stdout.read())>0:
            trust_convert=True
            print('warning:%s is hpux with trust-mode,convert to normal!'%(self.hostname))
            stdin,stdout,stder=self.client.exec_command('/etc/tsconvert -r')

        passfile={'hp-ux':'/etc/passwd','linux':'/etc/shadow','aix':'/etc/security/passwd'}[self.os_type]
        sftp=self.client.open_sftp()
        data=sftp.open(passfile,'r').read()
        if self.os_type in ('hp-ux','linux'):
            recs=[x.split(':') for x in data.split('\n')]
            rec=[x for x in recs if x[0]==username][0]
            rec[1]=self.make_crypt(password)
            data='\n'.join([':'.join(x) for x in recs])
        elif self.os_type == 'aix':
            recs=[x.strip().split('\n') for x in data.split('\n\n')]
            rec=[x for x in recs if x[0]=='root:'][0]
            rec[1]=u'\tpassword = '+ self.make_crypt(password)
            rec[2]=u'\tlastupdate = '+ str(int(time.time()))
            data='\n'.join(['\n'+'\n'.join(x) for x in recs])+'\n'
        else:
            print('ERROR:invalid os type:'+self.os_type)

        #backup passfile
        cmd='cp -pf %s /tmp/pass_%s.bak' % \
            (passfile,time.strftime('%Y%m%d_%H%M%S',time.localtime()))
        stdin,stdout,stderr=self.client.exec_command(cmd)
        out=stderr.read()
        if out:
            print("ERROR in backup",out)
        sftp.open(passfile,'w').write(data)
        if trust_convert:
            print('convert %s back to trust-mode!'%(self.hostname))
            stdin,stdout,stder=self.client.exec_command('/etc/tsconvert')

    def make_crypt(self,password):
        cmd='openssl passwd -crypt %s'%(password)
        stdin,stdout,stderr=self.client.exec_command(cmd)
        return stdout.read().strip()

    def get_os_type(self):
        stdin,stdout,stderr=self.client.exec_command('uname')
        out=stdout.read().strip().lower()
        return out


    def close(self):
        self.client.close()

def main():
    usage="""Usage:
    %s host user password newpass
    """ % (sys.argv[0],)*1
    if len(sys.argv)!=5:
        print(usage)
        quit()
    host,user,passwd,newpass=sys.argv[1:]
    try:
        ssh=ssh_util(host,22,user,passwd)
        print('os type is %s'%(ssh.os_type))
        ssh.passwd(user,newpass)
        ssh.close()
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()


if __name__ == '__main__':
    main()
