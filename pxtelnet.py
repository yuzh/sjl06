#encoding=utf-8
from pexpect import ExceptionPexpect, TIMEOUT, EOF, spawn
import time
import os

__all__ = ['ExceptionPxtelnet', 'pxtelnet']

# Exception classes used by this module.
class ExceptionPxtelnet(ExceptionPexpect):
    '''Raised for pxtelnet exceptions.
    '''
class pxtelnet (spawn):
    '''This class extends pexpect.spawn to specialize setting up SSH
    connections. This adds methods for login, logout, and expecting the shell
    prompt. It does various tricky things to handle many situations in the SSH
    login process. For example, if the session is your first login, then pxtelnet
    automatically accepts the remote certificate; or if you have public key
    authentication setup then pxtelnet won't wait for the password prompt.

    pxtelnet uses the shell prompt to synchronize output from the remote host. In
    order to make this more robust it sets the shell prompt to something more
    unique than just $ or #. This should work on most Borne/Bash or Csh style
    shells.

    Example that runs a few commands on a remote server and prints the result::

        import pxtelnet
        import getpass
        try:
            s = pxtelnet.pxtelnet()
            hostname = raw_input('hostname: ')
            username = raw_input('username: ')
            password = getpass.getpass('password: ')
            s.login (hostname, username, password)
            s.sendline ('uptime')  # run a command
            s.prompt()             # match the prompt
            print s.before         # print everything before the prompt.
            s.sendline ('ls -l')
            s.prompt()
            print s.before
            s.sendline ('df')
            s.prompt()
            print s.before
            s.logout()
        except pxtelnet.ExceptionPxtelnet, e:
            print "pxtelnet failed on login."
            print str(e)

    Note that if you have ssh-agent running while doing development with pxtelnet
    then this can lead to a lot of confusion. Many X display managers (xdm,
    gdm, kdm, etc.) will automatically start a GUI agent. You may see a GUI
    dialog box popup asking for a password during development. You should turn
    off any key agents during testing. The 'force_password' attribute will turn
    off public key authentication. This will only work if the remote SSH server
    is configured to allow password logins. Example of using 'force_password'
    attribute::

            s = pxtelnet.pxtelnet()
            s.force_password = True
            hostname = raw_input('hostname: ')
            username = raw_input('username: ')
            password = getpass.getpass('password: ')
            s.login (hostname, username, password)
    '''

    def __init__ (self, timeout=30, maxread=2000, searchwindowsize=None, logfile=None, cwd=None, env=None,debug=False):

        spawn.__init__(self, None, timeout=timeout, maxread=maxread, searchwindowsize=searchwindowsize, logfile=logfile, cwd=cwd, env=env)

        self.name = '<pxtelnet>'

        #SUBTLE HACK ALERT! Note that the command that SETS the prompt uses a
        #slightly different string than the regular expression to match it. This
        #is because when you set the prompt the command will echo back, but we
        #don't want to match the echoed command. So if we make the set command
        #slightly different than the regex we eliminate the problem. To make the
        #set command different we add a backslash in front of $. The $ doesn't
        #need to be escaped, but it doesn't hurt and serves to make the set
        #prompt command different than the regex.

        # used to match the command-line prompt
        self.UNIQUE_PROMPT = "\[PEXPECT\][\$\#] "
        self.PROMPT = self.UNIQUE_PROMPT

        # used to set shell command-line prompt to UNIQUE_PROMPT.
        self.PROMPT_SET_SH = "PS1='[PEXPECT]\$ '"
        self.PROMPT_SET_CSH = "set prompt='[PEXPECT]\$ '"
        self.SSH_OPTS = ("-o'RSAAuthentication=no'"
                + " -o 'PubkeyAuthentication=no'")
# Disabling host key checking, makes you vulnerable to MITM attacks.
#                + " -o 'StrictHostKeyChecking=no'"
#                + " -o 'UserKnownHostsFile /dev/null' ")
        # Disabling X11 forwarding gets rid of the annoying SSH_ASKPASS from
        # displaying a GUI password dialog. I have not figured out how to
        # disable only SSH_ASKPASS without also disabling X11 forwarding.
        # Unsetting SSH_ASKPASS on the remote side doesn't disable it! Annoying!
        #self.SSH_OPTS = "-x -o'RSAAuthentication=no' -o 'PubkeyAuthentication=no'"
        self.force_password = False
        self.auto_prompt_reset = True
        self.DEBUG=debug

    def levenshtein_distance(self, a,b):

        '''This calculates the Levenshtein distance between a and b.
        '''

        n, m = len(a), len(b)
        if n > m:
            a,b = b,a
            n,m = m,n
        current = range(n+1)
        for i in range(1,m+1):
            previous, current = current, [i]+[0]*n
            for j in range(1,n+1):
                add, delete = previous[j]+1, current[j-1]+1
                change = previous[j-1]
                if a[j-1] != b[i-1]:
                    change = change + 1
                current[j] = min(add, delete, change)
        return current[n]

    def sync_original_prompt (self):

        '''This attempts to find the prompt. Basically, press enter and record
        the response; press enter again and record the response; if the two
        responses are similar then assume we are at the original prompt. This
        is a slow function. It can take over 10 seconds. '''

        # All of these timing pace values are magic.
        # I came up with these based on what seemed reliable for
        # connecting to a heavily loaded machine I have.
        self.sendline()
        time.sleep(0.1)
        # If latency is worse than these values then this will fail.

        try:
            # Clear the buffer before getting the prompt.
            self.read_nonblocking(size=10000,timeout=1)
        except TIMEOUT:
            pass
        time.sleep(0.1)
        self.sendline()
        time.sleep(0.15)
        x = self.read_nonblocking(size=1000,timeout=1)
        time.sleep(0.1)
        self.sendline()
        time.sleep(0.15)
        a = self.read_nonblocking(size=1000,timeout=1)
        time.sleep(0.1)
        self.sendline()
        time.sleep(0.15)
        b = self.read_nonblocking(size=1000,timeout=1)
        ld = self.levenshtein_distance(a,b)
        len_a = len(a)
        if len_a == 0:
            return False
        if float(ld)/len_a < 0.4:
            return True
        return False

    def debug(self,s):
        if self.DEBUG:
            self._log('*** DEBUG:<'+s+'>DEBUG ***','debug')

    ### TODO: This is getting messy and I'm pretty sure this isn't perfect.
    ### TODO: I need to draw a flow chart for this.
    def login (self,server,username,password='',switch_port=23,terminal_type='ansi',original_prompt=r"[#$]",login_timeout=10,port=None,auto_prompt_reset=True,ssh_key=None):


        cmd = "telnet %s %d" % (server,switch_port)
        spawn._spawn(self, cmd)
        stage=0
        # stage=1 -> get "login:" prompt
        # stage=2 -> get "password:" prompt
        # stage=3 -> get shell prompt
        login_zh_utf8=u'登录：'.encode('utf8')
        login_zh_gbk=u'登录：'.encode('gbk')
        login_en='[Ll]ogin:'
        pass_zh_utf8=u'密码：'.encode('utf8')
        pass_zh_gbk=u'密码：'.encode('gbk')
        pass_en='[Pp]assword:'
        while True:
            if stage==0:
                exp_list=[
                    "(%s)|(%s)|(%s)"%(login_en,login_zh_utf8,login_zh_gbk),
                    "(?i)connection closed by (remote)|(foreign) host",
                    "(?i)Connection refused",
                    TIMEOUT,EOF ]
                i = self.expect( exp_list, timeout=login_timeout)
                if i==0:
                    stage=1 # get the login: prompt
                    self.debug('get login prompt('+self.after+')')
                else:
                    exp_msg=str(exp_list[i])
                    self.close()
                    raise ExceptionPxtelnet(exp_msg)
            elif stage==1:
                self.sendline(username)
                exp_list=[
                    "(%s)|(%s)|(%s)"%(pass_en,pass_zh_utf8,pass_zh_gbk),
                    original_prompt,
                    "(?i)connection closed by (remote)|(foreign) host",
                    "(?i)Connection refused",
                    TIMEOUT,EOF]
                i = self.expect( exp_list, timeout=login_timeout)
                if i==0:
                    stage=2 # get the passwd: prompt
                    self.debug('get passwd prompt('+self.after+')')
                elif i==1:
                    stage=3 # no passwd,into shell
                    break
                else:
                    exp_msg=str(exp_list[i])
                    self.close()
                    raise ExceptionPxtelnet(exp_msg)
            elif stage==2:
                self.sendline(password)
                exp_list=[
                    original_prompt, 
                    "(3004-300)|(Login incorrect)",
                    "(?i)terminal type", 
                    TIMEOUT]
                i = self.expect( exp_list,timeout=login_timeout)
                if i==0:
                    stage=3
                    self.debug('get shell('+self.after+')')
                    break
                elif i==2: #require teminal type
                    self.sendline('vt100')
                else:
                    exp_msg=str(exp_list[i])+'|'+self.after
                    self.close()
                    raise ExceptionPxtelnet(exp_msg)
        if not self.sync_original_prompt():
            self.close()
            raise ExceptionPxtelnet ('could not synchronize with original prompt')
        # We appear to be in.
        # set shell prompt to something unique.
        if auto_prompt_reset:
            if not self.set_unique_prompt():
                self.close()
                raise ExceptionPxtelnet ('could not set shell prompt\n'+self.before)
        return True

    def logout (self):

        '''This sends exit to the remote shell. If there are stopped jobs then
        this automatically sends exit twice. '''

        self.sendline("exit")
        index = self.expect([EOF, "(?i)there are stopped jobs"])
        if index==1:
            self.sendline("exit")
            self.expect(EOF)
        self.close()

    def prompt (self, timeout=-1):

        '''This matches the shell prompt. This is little more than a short-cut
        to the expect() method. This returns True if the shell prompt was
        matched. This returns False if a timeout was raised. Note that if you
        called :meth:`login` with :attr:`auto_prompt_reset` set to False then
        before calling :meth:`prompt` you must set the :attr:`PROMPT` attribute
        to a regex that it will use for matching the prompt.

        Calling :meth:`prompt` will erase the contents of the :attr:`before`
        attribute even if no prompt is ever matched. If timeout is not given or
        it is set to -1 then self.timeout is used.
        '''

        if timeout == -1:
            timeout = self.timeout
        i = self.expect([self.PROMPT, TIMEOUT], timeout=timeout)
        if i==1:
            return False
        return True

    def set_unique_prompt (self):

        '''This sets the remote prompt to something more unique than # or $.
        This makes it easier for the :meth:`prompt` method to match the shell prompt
        unambiguously. This method is called automatically by the :meth:`login`
        method, but you may want to call it manually if you somehow reset the
        shell prompt. For example, if you 'su' to a different user then you
        will need to manually reset the prompt. This sends shell commands to
        the remote host to set the prompt, so this assumes the remote host is
        ready to receive commands.

        Alternatively, you may use your own prompt pattern. Just set the PROMPT
        attribute to a regular expression that matches it. In this case you
        should call login() with auto_prompt_reset=False; then set the PROMPT
        attribute. After that the prompt() method will try to match your prompt
        pattern.'''

        self.sendline ("unset PROMPT_COMMAND")
        self.sendline (self.PROMPT_SET_SH) # sh-style
        i = self.expect ([TIMEOUT, self.PROMPT], timeout=10)
        if i == 0: # csh-style
            self.sendline (self.PROMPT_SET_CSH)
            i = self.expect ([TIMEOUT, self.PROMPT], timeout=10)
            if i == 0:
                return False
        return True

def main():
    test_cases=(
        ('10.112.9.63','root','rot'),
        ('10.112.15.67','root','root'),
    )
    for host,user,passwd in test_cases:
        print('login',host,user,passwd)
        try:
            s=pxtelnet(logfile=open('/tmp/pxtelnet_%s.log'%(host),'w'))
            s.DEBUG=True
            s.login(host,user,passwd)
            s.sendline('uname -a')
            s.prompt()
            print(s.before,s.after)
            s.logout()
        except ExceptionPxtelnet,e:
            print(e)

if __name__=='__main__':
    #main()
# vi:ts=4:sw=4:expandtab:ft=python:
