#encoding=utf-8
import sys
import time
import os
import paramiko
import traceback
__all__ = ['ssh_util']
from zbxapi import ZabbixApi

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

class zbx_util(ssh_util):
    def execute(self,cmd):
        print 'zbx_util.execute',cmd
        cfgfile=os.environ.get('ZABBIX_CONFIG')
        if not cfgfile:
            cfgfile=os.path.dirname(sys.argv[0])+'/zbx.cfg'
        cfg=dict([x.strip().split('=') for x in open(cfgfile).readlines()])
        self.za=ZabbixApi(cfg['server'],cfg['user'],cfg['password'])

        func={'status':self.status,'start':self.start,'stop':self.stop,
            'reg':self.reg,'unreg':self.unreg,
            'install':self.install,'remove':self.remove}.get(cmd)
        if func:
            
            return func()
        else:
            return 'bad zbx cmd (%s)'%(cmd)

    def _uname_a(self):
        stdin,stdout,stderr=self.client.exec_command('uname -a')
        self.uname_a=stdout.read().strip().lower()
        return self.uname_a
        #ret['uname']=self.uname_a

    def _zbx_proc_num(self):
        stdin,stdout,stderr=self.client.exec_command('ps -u zabbix')
        self.zbx_proc_num=stdout.read().strip().lower().count('zabbix_agentd')
        return self.zbx_proc_num

    def _zbx_file_num(self):
        stdin,stdout,stderr=self.client.exec_command('ls /home/zabbix')
        self.zbx_file_num=len(stdout.read().strip().lower().split())
        return self.zbx_file_num

    def _zbx_host_id(self):
        try:
            self.zbx_hostid=self.za.host_get_byname(self.hostname)
        except Exception as e:
            self.zbx_hostid=None
        return self.zbx_hostid

    def status(self):
        ret={
            'uname'         :self._uname_a(),
            'zbx_proc_num'  :self._zbx_proc_num(),
            'zbx_file_num'  :self._zbx_file_num(),
            'zbx_host_id'   :self._zbx_host_id(),
            }
        return ret

    def start(self):
        ret=self.status()
        if self.zbx_proc_num>0:
            return {'error':'zabbix already running!'}
        if self.zbx_file_num<10:
            return {'error':'zabbix not install!'}
        #if not self.zbx_hostid:
        #    return {'error':'host not registe on zabbix server!'}
        stdin,stdout,stderr=self.client.exec_command('/home/zabbix/zbxrun.sh')
        out=stdout.read()
        return {'start':out}

    def stop(self):
        ret=self.status()
        if self.zbx_proc_num==0:
            return {'error':'zabbix not running!'}
        stdin,stdout,stderr=self.client.exec_command('/home/zabbix/zbxstop.sh')
        out=stdout.read()
        return {'stop':out}

    def _mk_nodename(self):
        self._uname_a()
        ip=self.hostname
        hostname=self.uname_a.split()[1]
        nodename=hostname+'_'+ip[ip.find('.',3)+1:]
        return nodename
        
    def _do_cmd(self,cmd):
        stdin,stdout,stderr=self.client.exec_command(cmd)
        print('CMD:'+cmd)
        out=stdout.read()
        err=stderr.read()
        print('OUT:'+out)
        print('ERR:'+err)
        return {'out':out,'err':err}

    def _install(self):
        pkgs={
            'aix53'   :'zabbix_aix53.tar.gz',
            'aix61'   :'zabbix_agents_2.0.6.aix6100.powerpc.tar.gz',
            'hppa11'  :'zabbix_agents_2.0.6.hpux11_11.risc.tar.gz',
            'hppa23'  :'zabbix_agents_2.0.6.hpux11_23.risc.tar.gz',
            'hpia23'  :'zabbix_ia23.tar.gz',
            'hpia31'  :'zabbix_agents_2.0.6.hpux11_31.ia64.tar.gz',
            'hppa31'  :'zabbix_agents_2.0.6.hpux11_31.risc.tar.gz',
            'linux64' :'zabbix_agents_2.0.6.linux2_6_23.amd64.tar.gz',
            'linux32' :'zabbix_agents_2.0.6.linux2_6_23.i386.tar.gz',
            'win'     :'zabbix_agents_2.0.6.win.zip',
        }
        zbx_cfg='/mnt/kit/tools/zabbix/zabbix_agentd.conf.std'
        zbx_cfg_os=None

        uname=self._uname_a()
        ostype=uname.split()[0].lower()
        hostname=uname.split()[1]
        if ostype=='aix':
            zbx_cfg_os='/mnt/kit/tools/zabbix/zabbix_agentd.conf.aix'
            osver=uname.split()[3]
            if osver=='5':
                pkg='aix53'
            else:
                pkg='aix61'
        if ostype=='hp-ux':
            zbx_cfg_os='/mnt/kit/tools/zabbix/zabbix_agentd.conf.hp'
            osver=uname.split()[2][-2:]
            platform=uname.split()[4][:2]
            if platform=='ia':
                pkg='hpia'+osver
            else:
                pkg='hppa'+osver
        if ostype=='linux':
            if '86_64' in uname:
                pkg='linux64'
            else:
                pkg='linux32'
        pkgfile='/mnt/kit/tools/zabbix/pkgs/'+pkgs[pkg]

        #upload the binary package
        sftp=self.client.open_sftp()
        sftp.put(pkgfile,'/tmp/'+pkgs[pkg])
        #create zabbix group
        if ostype=='aix':
            cmd='mkgroup zabbix'
        else:
            cmd='groupadd zabbix'
        self._do_cmd(cmd)
        #create zabbix user
        cmd='useradd -g zabbix -d /home/zabbix -m zabbix'
        self._do_cmd(cmd)
        #extract package
        cmd='cd /home/zabbix;PATH=$PATH:/usr/contrib/bin;gzip -dc /tmp/%s|tar xvf -'%(pkgs[pkg])
        self._do_cmd(cmd)
        #create zabbix conf file
        buf=open(zbx_cfg).read()
        buf=buf+"\nHostname=%s\n"%(hostname)
        if zbx_cfg_os:
            buf=buf+open(zbx_cfg_os).read()
        sftp.open('/home/zabbix/zabbix_agentd.conf','w').write(buf)

        #create utility scripts
        head='#auto create by install program %s\n'%(time.asctime())
        #create zbxrun.sh
        buf='/home/zabbix/sbin/zabbix_agentd -c /home/zabbix/zabbix_agentd.conf\n'
        sftp.open('/home/zabbix/zbxrun.sh','w').write(head+buf)
        #create zbxstop.sh
        if ostype=='linux':
            buf="ps -u zabbix|awk '{print \$2}'|grep -v PID|xargs -n 1 kill -9"
        else:
            buf="ps -u zabbix|awk '{print \$1}'|grep -v PID|xargs -n 1 kill -9"
        sftp.open('/home/zabbix/zbxstop.sh','w').write(head+buf)
        cmd='cd /home/zabbix;chmod +x zbx*.sh'
        self._do_cmd(cmd)

        #create startup links
        if ostype=='aix':
            cmd='ln -s /home/zabbix/zbxrun.sh /etc/rc.d/rc2.d/S99zabbix'
        if ostype=='hp-ux':
            cmd='ln -s /home/zabbix/zbxrun.sh /sbin/rc3.d/S99zabbix'
        if ostype=='linux':
            cmd='ln -s /home/zabbix/zbxrun.sh /etc/rc.d/rc2.d/S99zabbix'
        self._do_cmd(cmd)

    def install(self):
        r0=self._install()
        r1=self.start()
        r2=self.reg()
        r1.update(r2)
        return r1

    def _remove(self):
        r=dict()
        stdin,stdout,stderr=self.client.exec_command('rm -rf /home/zabbix')
        r['rm zabbix dir']=stdout.read()
        stdin,stdout,stderr=self.client.exec_command('userdel zabbix')
        r['del zabbix user']=stdout.read()
        return r
        
    def remove(self):
        r1=self.stop()
        r2=self.unreg()
        r3=self._remove()
        r1.update(r2)
        r1.update(r3)
        return r1

    def reg(self):
        nodename=self._mk_nodename()
        hostid=self._zbx_host_id()
        if hostid:
            msg=self.za.host_enable(self.zbx_hostid,0,nodename)
        else:
            uname=self.uname_a.split()[0].lower()
            unameGroup={
                'aix'  :'Aix',
                'hp-ux':'Hpux',
                'linux':'Linux',
            }
            group=unameGroup[uname]
            groupTemplate={
                'Aix'  :'Template OS Aix',
                'Hpux' :'Template OS HP-UX',
                'Linux':'Template OS Linux',
            }
            template=groupTemplate[group]
            ip=self.hostname
            if template:
                print(ip,nodename,group,template,uname)
                try:
                    msg=self.za.host_create(ip,nodename,group,template)
                except ValueError as e:
                    msg='%s,%s'%(e.__class__,e)
            else:
                msg='group error:%s is not in %s'%(group,`groupTemplate.keys()`)
        return {'reg:':msg,'nodename':nodename}

    def unreg(self):
        nodename=self._mk_nodename()
        hostid=self._zbx_host_id()
        if hostid:
            newname='%s disable on %s'%(nodename,time.strftime('%x-%X',time.localtime()) )
            msg=self.za.host_enable(self.zbx_hostid,1,newname)
        else:
            msg='%s has not register on zabbix'%(nodeame)
        return {'unreg:':msg,'nodename':newname}

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
