#encoding=utf8
import sys
import pyDes
import binascii
import cPickle
"""
2013-5-16 初次创建
"""
lmkList={
    '10.112.9.249': '79B6244A59B249D74D9C1CFA429C25E779B6244A59B249D7',
    '10.112.9.244': '79B6244A59B249D74D9C1CFA429C25E779B6244A59B249D7',
    '10.112.9.244': '79B6244A59B249D74D9C1CFA429C25E779B6244A59B249D7',
    '10.112.9.208': '111111111111111111111111111111111111111111111111',
    '10.112.9.246': '111111111111111111111111111111111111111111111111',
}
def convert_text(ip):
    # 必须将ipaddr.txt文件（通过getallkey.py获取）放置在当前目录下
    # 生成ipaddr.hsm文件，也产生在当前目录下
    lmk=lmkList[ip]
    buf=open(ip+'.txt').readlines()
    t1=[x.strip().split() for x in buf]
    t2=[x for x in t1 if x[1][:4]=='2D00']
    t3=[(int(x[0]),x[1][5:5+{'1':16,'2':32,'3':48}[x[1][4]]]) for x in t2]
    LMK=binascii.unhexlify(lmk)
    des=pyDes.triple_des(LMK)
    HSM={\
        'lmk':LMK,\
        'password':'FFFFFFFF',\
        'authorized':False,\
        'keys':{},\
        'whitelist':[],\
    }
    for x in t3:
        cipher=binascii.unhexlify(x[1])
        clear=des.decrypt(cipher)
        HSM['keys'][x[0]]=clear
        print(x[0],binascii.hexlify(clear))
    cPickle.dump(HSM,open(ip+'.hsm','w'))
    
if __name__=='__main__':
    if len(sys.argv)==2:
        convert_text(sys.argv[1])
    else:
        #for ip in lmkList.keys():
        #    convert_text(ip)
        print('Usage:txt2hsm ip_address')

