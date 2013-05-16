import sys
import socket
import struct

def gen_pkg(buf):
    return struct.pack('>h',len(buf))+buf

def unpkg(buf):
    pkglen=struct.unpack('>h',buf[:2])[0]
    return (pkglen,buf[2:2+pkglen])

if __name__=='__main__':
    if len(sys.argv)!=2:
        print('Usage:getallkey.py hsmip')
        exit(1)
    HOST=sys.argv[1] # '10.112.9.249'
    PORT=8
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    #cmds=('HR','2CK000','2CK001')
    #cmds=['2CK%03X' % (x) for x in range(4096)]
    #for cmd in cmds:
    for i in range(4096):
        cmd='2CK%03X'%(i)
        buf=gen_pkg(cmd)
        s.send(buf)
        ret=s.recv(8192)
        print i,unpkg(ret)[1]
    s.close()
