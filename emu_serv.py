#encoding=utf8
#!/usr/bin/env python
"""
2013-05017:增加127.0.0.1为允许的客户端
    支持spdb开始的内容作为控制指令，包括help、exit、addip
2013-7-22:新版本，通过实体加密机支持，进行加密运算。
    虚拟加密机只进行密文存储和报文格式转换（密钥索引转密文）
    需要指定真实加密机的地址/端口，类型（直连还是平台转），密钥文件，本地端口；5个参数
"""
import sys
import asyncore
import socket
import struct
import emu_hsm
import pprint

def gen_pkg(buf):
    return struct.pack('>h',len(buf))+buf

def unpkg(buf):
    pkglen=struct.unpack('>h',buf[:2])[0]
    return (pkglen,buf[2:2+pkglen])

class EmuHandler(asyncore.dispatcher_with_send):
    def __init__(self,sock,hsm,allow_ip,map=None):
        asyncore.dispatcher_with_send.__init__(self,sock,map)
        self.buf=''
        self.hsm=hsm
        self.allow_ip=allow_ip

    def sethsm(self,hsm):
        self.hsm=hsm
        print 'hsm set to ',`hsm`

    def handle(self,Req):
        if Req[0]>='a' and Req[0]<='z':
            buf=self.handle_cmd(Req.split())
        else:
            buf=self.hsm.handle(Req)
        return buf

    def handle_cmd(self,cmd):
        pp=pprint.PrettyPrinter(indent=4)
        if cmd[0]=='exit':
            if len(cmd)>1 and cmd[1]=='password':
                self.send(gen_pkg('bye'))
                self.close()
                self.hsm.close()
                print('HSM EMU Server shutdown!')
                exit(0)
            else:
                return 'need password!'
        elif cmd[0]=='help':
            return 'HSM Emu server,support commands:\n'\
                'help\n'\
                'exit <shutdown_password>\n'\
                'save\n'\
                'addip client_ip\n'\
                'delip client_ip\n'\
                'status\n'
        elif cmd[0]=='status':
            text='socket list'+'\n'
            #for x in asyncore.socket_map.values():
            #    text+='    '+`x.addr`+'\n'
            text=pp.pformat(asyncore.socket_map.values())+'\n'
            text+='hsm stats:\n'
            stats=dict([x for x in self.hsm.stats.items() if x[1]>0])
            text+=pp.pformat(stats)+'\n'
            text+='allow_ip:'+`self.allow_ip`+'\n'
            text+='total %d keys\n'%(len(self.hsm.KEYS))
            return text
        elif cmd[0]=='save':
            self.hsm.save()
            return 'save %d keys\n'%(len(self.hsm.KEYS))
        elif cmd[0]=='addip':
            self.allow_ip.append(cmd[1])
            return '%s add to allow list\n'%(cmd[1])
        elif cmd[0]=='delip':
            try:
                self.allow_ip.remove(cmd[1])
            except ValueError,e:
                return 'remove %s fail:%s\n'%(cmd[1],e[0])
            else:
                return 'remove %s from allow list\n'%(cmd[1])
        else:
            return 'unknown command'

    def handle_read(self):
        data = self.recv(8192)
        if data:
            #self.send(data)
            #return
            self.buf+=data
            if len(self.buf)>2:
                cmdlen=2+struct.unpack('>h',self.buf[:2])[0]
                #print 'packlen is %d' % (cmdlen)
                if len(self.buf)>=cmdlen:
                    Req=self.buf[2:cmdlen]
                    self.buf=self.buf[cmdlen:]
                    buf=self.handle(Req)
                    Res=struct.pack('>h',len(buf))+buf
                    self.send(Res)


class EmuServer(asyncore.dispatcher):

    def __init__(self, conf):
        asyncore.dispatcher.__init__(self)
        print('EmuServer Config')
        pprint.PrettyPrinter(indent=4).pprint(conf)
        self.allow_ip=conf.get('allow_ip','127.0.0.1').split(',')
        self.hsm=emu_hsm.Hsm(conf)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        host=conf.get('listen_ip','0.0.0.0')
        port=int(conf.get('listen_port',10008))
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            #print 'Incoming connection from %s' % repr(addr)
            #print addr[0]
            if addr[0] in self.allow_ip:
                self.hsm.logflag='%s:%d\n'%addr
                handler = EmuHandler(sock,self.hsm,self.allow_ip)
            else:
                sock.send(gen_pkg('You r not my client!'))
                sock.close()

def loadConfig(fname):
    """
    A config file will be following lines:
    listen_ip=0.0.0.0
    listen_port=10008
    real_hsm_ip=10.112.18.22
    real_hsm_port=10091
    hsm_prefix=001001
    hsm_data=9.249.keys
    allow_ip=127.0.0.1,10.112.18.22
    """
    buf=open(fname).readlines()
    return dict([x.strip().split('=') for x in buf if x[0]!='#'])

if __name__=='__main__':
    if len(sys.argv)!=2:
        print('Usage:emu_serv.py config_file')
        exit(0)
    conf=loadConfig(sys.argv[1])
    server = EmuServer(conf)
    asyncore.loop()
