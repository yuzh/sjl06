#!/usr/bin/env python

import asyncore
import socket
import struct
import emu_hsm

class EmuHandler(asyncore.dispatcher_with_send):
    def __init__(self,sock,hsm,map=None):
        asyncore.dispatcher_with_send.__init__(self,sock,map)
        self.buf=''
        self.hsm=hsm

    def sethsm(self,hsm):
        self.hsm=hsm
        print 'hsm set to ',`hsm`

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
                    Res=self.hsm.handle(Req)
                    self.send(Res)


class EmuServer(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.hsm=emu_hsm.Hsm('hsm.dat')
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
            handler = EmuHandler(sock,self.hsm)

server = EmuServer('0.0.0.0', 10008)
asyncore.loop()
