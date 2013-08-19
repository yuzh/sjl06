#!/usr/bin/env python
#encoding=utf-8
"""
将加密机中的密钥从MK加密转移为KEK加密，并将密文输出到文件中
2013-8-19 创建
"""
import sys
import cPickle
from emu_hsm import HsmComm,loadConfig

def loadKeyPos(fname):
    t1=[x.split() for x in open(fname).readlines()]
    t2=[int(x[-1][-4:]) for x in t1 if len(x)>1]
    return list(set(t2))

def mk2kek(hsm,keypos_list,kek_pos,kek_len):
    kpos='K'+('%X'%(kek_pos))[-3:]
    keys_kek=dict()
    for k in keypos_list:
        #first read the source key
        cmd='2CK'+('%03X'%(k))[-3:]
        rlt=hsm.send_recv(cmd)
        if rlt[:4]=='2D00':
            keylen=rlt[4]
            if keylen in '123':
                buf=rlt[4:4+1+int(keylen)*16]
                cmd='1E'+'1'+str(kek_len)+kpos+buf
                rlt=hsm.send_recv(cmd)
                if rlt[:4]=='1F00':
                    buf=rlt[4:]
                    cipher=rlt[:-16]
                    check=rlt[-16:]
                    keys_kek[k]=(cipher,check)
                else:
                    print("mk2kek:1E cmd fail",cmd,rlt)
            else:
                print("mk2kek:invalid keylen",k,rlt)
        else:
            print("mk2kek:read key fail",k,rlt)
    return keys_kek

        
def main():
    conf=loadConfig('mk_kek.conf')
    hsm_ip    =conf.get('src_hsm_ip','10.112.18.22')
    hsm_port  =int(conf.get('src_hsm_port','10010'))
    hsm_prefix=conf.get('src_hsm_prefix','001001')
    src_hsm = HsmComm(hsm_ip,hsm_port,hsm_prefix)
    if not src_hsm.open():
        print('Unable open source HSM!')
        sys.exit(1)

    #keypos_file=conf.get('keypos_file','inavailablekeypos')
    #这个文件用 echo|mngKeySpace -pinavailablekeypos>/tmp/inavailablekeypos 生成
    #keypos_list=loadKeyPos(keypos_file)
    keypos_list=range(0,4096)

    kek_pos=int(conf.get('kek_pos','4090'))
    kek_len=int(conf.get('kek_len','3'))
    kek_file=conf.get('kek_file','ciphers.kek')

    keys_kek=mk2kek(src_hsm,keypos_list,kek_pos,kek_len)
    cPickle.dump(keys_kek,open(kek_file,'w'))


if __name__=='__main__':
    main()
