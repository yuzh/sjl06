#encoding=utf8
#!/usr/bin/env python
"""
2013-05017:增加127.0.0.1为允许的客户端
    支持spdb开始的内容作为控制指令，包括help、exit、addip
"""
import sys
import asyncore
import socket
import struct
import emu_hsm

def gen_pkg(buf):
    return struct.pack('>h',len(buf))+buf

def unpkg(buf):
    pkglen=struct.unpack('>h',buf[:2])[0]
    return (pkglen,buf[2:2+pkglen])

class EmuHandler(asyncore.dispatcher_with_send):
    def __init__(self,sock,hsm,map=None):
        asyncore.dispatcher_with_send.__init__(self,sock,map)
        self.buf=''
        self.hsm=hsm

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
        if cmd[0]=='exit':
            self.send(gen_pkg('bye'))
            self.close()
            print('HSM EMU Server shutdown!')
            exit(0)
        elif cmd[0]=='help':
            return 'HSM Emu server,support commands:\n'\
                'help\n'\
                'exit\n'\
                'status\n'\
                'addip[ipaddr]\n'
        elif cmd[0]=='addip':
            print 'origin',self.hsm.HSM['whitelist']
            self.hsm.HSM['whitelist'].append(cmd[1])
            print 'new',self.hsm.HSM['whitelist']
            return 'add ip %s ok' % (cmd[1])
        elif cmd[0]=='status':
            text='whitelist'+`self.hsm.HSM['whitelist']`+'\n'
            text+='socketlist'+'\n'
            for x in asyncore.socket_map.values():
                text+='    '+`x.addr`+'\n'
            return text
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
                print 'packlen is %d' % (cmdlen)
                if len(self.buf)>=cmdlen:
                    Req=self.buf[2:cmdlen]
                    self.buf=self.buf[cmdlen:]
                    buf=self.handle(Req)
                    Res=struct.pack('>h',len(buf))+buf
                    self.send(Res)


class EmuServer(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        print('loading %s'%(sys.argv[1]))
        self.hsm=emu_hsm.Hsm(sys.argv[1])
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            print 'Incoming connection from %s' % repr(addr)
            print addr[0]
            if addr[0] in self.hsm.HSM['whitelist'] or addr[0]=='127.0.0.1':
                handler = EmuHandler(sock,self.hsm)
            else:
                sock.send(gen_pkg('You r not my client!'))
                sock.close()

if __name__=='__main__':
    if len(sys.argv)!=2:
        print('Usage:emu_serv.py hsmfilename')
        exit(0)
    server = EmuServer('0.0.0.0', 10008)
    asyncore.loop()
