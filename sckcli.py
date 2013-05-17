#encoding=utf8
import sys
import os
import socket
import struct

"""
socket客户端，用于向加密机发送指令。
从环境变量HSM_HOST/HSM_PORT读取目标地址和端口信息。
2013-05-17 初次创建 
"""
def gen_pkg(buf):
    return struct.pack('>h',len(buf))+buf

def unpkg(buf):
    pkglen=struct.unpack('>h',buf[:2])[0]
    return (pkglen,buf[2:2+pkglen])

if __name__=='__main__':
    if len(sys.argv)!=2:
        print('Usage:sckcli.py msgtext')
        exit(1)
    HOST=os.environ.get('HSM_HOST')
    if not HOST:
        print('HSM_HOST not define! use 127.0.0.1')
        HOST='127.0.0.1'
    PORT=os.environ.get('HSM_PORT')
    if not PORT:
        print('HSM_PORT not define! use 10008')
        PORT='10008'
    PORT=int(PORT)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST,PORT))

    cmd=sys.argv[1]
    s.send(gen_pkg(cmd))
    ret=s.recv(8192)
    s.close()

    msglen,msg=unpkg(ret)
    print('[return %d bytes]'%( msglen))
    print msg
