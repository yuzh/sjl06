#!/usr/bin/env python
#encoding=utf-8
"""
将密钥文件中用KEK加密的密文，转换为用MK加密的密文，并输出文件中
2013-8-19 创建
"""
import sys
import cPickle
from emu_hsm import HsmComm,loadConfig
from mk2kek import getKey

def kek2mk(hsm,key_list,kek_pos):
    kek_len,kek,kek_chk=getKey(hsm,kek_pos)
    keys_mk=dict()
    for k in key_list.keys():
        cipher,check=key_list.get(k)
        keylen={48:'3',32:'2',16:'1'}[len(cipher)]
        cmd='1E'+'2'+kek_len+kek+keylen+cipher
        rlt=hsm.send_recv(cmd)
        if rlt[:4]=='1F00':
            buf=rlt[4:]
            cipher=buf[:-16]
            check=buf[-16:]
            keys_mk[k]=(cipher,check)
        else:
            print("mk2kek:1E cmd fail",cmd,rlt)
    return keys_mk

        
def main():
    conf=loadConfig('mk_kek.conf')
    hsm_ip    =conf.get('target_hsm_ip','10.112.18.43')
    hsm_port  =int(conf.get('target_hsm_port','19102'))
    hsm_prefix=conf.get('target_hsm_prefix','001001')
    target_hsm = HsmComm(hsm_ip,hsm_port,hsm_prefix)
    if not target_hsm.open():
        print('Unable open source HSM!')
        sys.exit(1)


    kek_pos=int(conf.get('kek_swap','4090'))
    kek_file=conf.get('kek_file','ciphers.kek')
    keys_kek=cPickle.load(open(kek_file))

    keys_mk=kek2mk(target_hsm,keys_kek,kek_pos)
    mk_file=conf.get('mk_file','ciphers.mk')
    cPickle.dump(keys_mk,open(mk_file,'w'))

    target_hsm.close()

if __name__=='__main__':
    main()
