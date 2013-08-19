#!/usr/bin/env python
#encoding=utf-8
"""
（HR/HS）   读密码机信息
（2A/2B）   存储一个MK加密的密钥至指定的索引位置
（2C/2D）   读取一个指定的索引的密钥
（80/81）   产生MAC
（60/61）   加密一个PIN
（62/63）   转换PIN从一个区域到另一个区域
（1E/1F）   在MK及KEK加密的密钥之间的转换
（1C/1D）   生成一个随机密钥，并用MK加密输出

2013/8/6 重构代码，通过实体加密机实现指令功能
"""
import cPickle
import struct
import socket

class HsmComm():
    def __init__(self,ip,port,prefix):
        self.hsm_ip=ip
        self.hsm_port=port
        self.hsm_prefix=prefix

    def open(self):
        self.hsm_sock=None
        try:
            self.hsm_sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.hsm_sock.connect((self.hsm_ip,self.hsm_port))
        except socket.error,msg:
            print("HsmComm.open fail,",msg)
            return False
        return True

    def recv(self):
        buf=self.hsm_sock.recv(8192)
        pkglen=struct.unpack('>h',buf[:2])[0]
        pkg=buf[2:2+pkglen]
        if self.hsm_prefix:
            pf_len=len(self.hsm_prefix)
            pkg=pkg[pf_len+2:]
            pkglen-=pf_len+2
        return (pkglen,pkg)

    def send_recv(self,data):
        buf=self.hsm_prefix+data
        buf=struct.pack('>h',len(buf))+buf
        self.hsm_sock.send(buf)
        pkglen,pkg=self.recv()
        return pkg

    def close(self):
        if self.hsm_sock:
            self.hsm_sock.close()

class Hsm(HsmComm):
    def __init__(self,conf):
        self.hsmfile=conf.get('hsm_data')
        self.load(self.hsmfile)

        hsm_ip=conf.get('real_hsm_ip')
        hsm_port=int(conf.get('real_hsm_port'))
        hsm_prefix=conf.get('hsm_prefix')
        HsmComm.__init__(self,hsm_ip,hsm_port,hsm_prefix)
        self.open()

        self.reserve_index=int(conf.get('reserve_index'))

        self.FuncMap={}
        # 查找Hsm类中所有形如handle_XX的函数，注册到函数映射表中
        funcs=[x for x in dir(Hsm) \
            if callable(getattr(self,x)) and x[:7]=='handle_']
        # {'XX':handle_XX}
        for f in funcs:
            self.FuncMap[f[-2:]]=getattr(self,f)

    def close(self):
        self.save()
        HsmComm.close(self)

    def handle(self,data):
        code=data[:2]
        if code in ('HR','2A','2C','1E','1C','60','62','63','80'):
            return self.FuncMap.get(data[:2])(data)
        else:
            print('Invalid request %s'%(data))
            return None

    def handle_HR(self,data):
        return self.send_recv('HR')

    def even_chk_part(self,ch):#奇校验部分
     return ch^(1-[y>0 and 1 or 0 for y in [ch&x for x in (128,64,32,16,8,4,2,1)]].count(1)%2)

    def even_chk(self,chk):#奇校验,16进制未展开，/OX形式
        return ''.join([chr(self.even_chk_part(ord(x))) for x in chk])

    def handle_1C(self,data):
        rest=data[2:]
        keylen=rest[0]
        if keylen not in '123':
            return '1C22'
        pkg = self.send_recv(data[:3])
        newidx = data[3:]
        if pkg[:4]=='1D00' and newidx and newidx[0]=='K':
            try:
                keyindex = int(newidx[1:],16)
                if keyindex<0 or keyindex>4095:
                    raise ValueError
            except ValueError:
                return '1C33'
            t=int(keylen)*16
            cipher = pkg[4:4+t]
            check = pkg[4+t:4+t+16]
            self.KEYS[keyindex]=(cipher,check)
        return pkg
        
    def handle_1E(self,data):
        """
        （1E/1F）   在MK及KEK加密的密钥之间的转换
        输入指令：2+1+1+(1A+3H)/（16/32/48）+1+16/32/48+4（可选）
            2:'1E'
            1:'1'->从MK加密到KEK加密(输入KEK索引) '2'->从KEK加密到MK加密（输入MK加密KEK密钥）
            1:1->64bit,2->128bit,3->192bit
            (1A+3H)/（16/32/48）：(1A+3H)->KEK索引：K+3N （16/32/48）->由MK加密的密钥
            1：WK单倍长 1->64bit,2->128bit,3->192bit
            16/32/48：MK或KEK加密下的密文
            4（可选）：如果该字段存在，转换后的密钥保存至该索引号中  如‘K003’

        输出结果：2+2+16/32/48+16
            2:"1F"
            2:错误代码，00表示正确
            16/32/48:转换后KEK或MK加密下的WK
            16:WK校验值
        req='1E'+'1'+'1'+'1C0BE608104E8118'+'1'+'D5D44FF720683D0D'
        expect='1F00'+'B6D1898291A4EF73'+'FCB2E54831F3EC60'
        """
        code,flag = struct.unpack('2s1s',data[:3])
        if code != '1E':
            return '1F60' #无此命令
        if flag not in '12':
            return '1F77' #非法字符
        rest = data[3:]
        try:
            keylen=rest[0]
            cipher,rest=self.replace_key(rest)
        except ValueError, e:
            return '1E'+e[0]
        try:
            wklen=rest[0]
            wk,rest=self.replace_key(rest)
        except ValueError , e:
            return '1E'+e[0]

        buf='1E'+flag+keylen+cipher+wklen+wk+rest
        print('debug handle_1E',buf)
        pkg=self.send_recv(buf)
        if pkg[:4]=='1F00' and rest and rest[0]=='K': #save result to hsm
            cipher = pkg[4:4+int(wklen)*16]
            check = pkg[4+int(wklen)*16:]
            keyindex = int(rest[1:4],16)
            self.KEYS[keyindex]=(cipher,check)
        return pkg

    def handle_2A(self,data):
        """
        （2A/2B）   存储一个MK加密的密钥至指定的索引位置
        输入指令：2+4+1+16/32/48
            2:"2A"
            4:"K"+3位16进制索引号
            1:1->64bit,2->128bit,3->192bit
            16/32/48:由MK加密的密钥
        输出结果：2+2+16
            2:"2B"
            2:错误代码，00表示正确
            16:单、双、三倍长密钥加密64比特 0的结果。
        """
        code,hexindex,keylen=struct.unpack('3s3s1s',data[:7])
        if code!='2AK':
            return '2B60' #无此命令
        try:
            keyindex=int(hexindex,16)
            if keyindex<1 or keyindex>4095:
                raise ValueError
        except ValueError:
            return '2B33' #密钥索引错
        if keylen not in '123':
            return '2B22' #密钥长度与使用模式不符
        
        cipher=data[7:]
        buf=code+'%03X'%(self.reserve_index)+keylen+cipher
        pkg=self.send_recv(buf)
        if pkg[:4]=='2B00':
            check=pkg[4:]
            self.KEYS[keyindex]=(cipher,check)
        return pkg

    def handle_2C(self,data):
        """
        （2C/2D）   读取一个指定的索引的密钥
        输入指令：2+4
            2:"2C"
            4:"K"+3位16进制索引号(密钥在密码机中要存放的位置（如：K001）)
           
        输出结果：2+2+1+16/32/48+16
            2:"2D"
            2:错误代码，00表示正确
            1:1->64bit,2->128bit,3->192bit
            16/32/48:用主密钥加密的工作密钥密文
            16:单、双、三倍长密钥加密64比特 0的结果。
        """
        code,hexindex=struct.unpack('3s3s',data[:6])
        if code!='2CK':
            return '2D60' #无此命令
        try:
            keyindex=int(hexindex,16)#取得密钥索引
            if keyindex<1 or keyindex>4096:
                raise ValueError
        except ValueError:
            return '2D33' #密钥索引错
        
        cipher,check=self.KEYS.get(keyindex)#取出密钥
        keylen='%1d'%(len(cipher)/16)
        result='2D00'+keylen+cipher.upper()+check.upper()
        return result

    def replace_key(self,data):
        rest=data
        keylen = rest[0]
        rest = rest[1:]
        #print('debug replace_key',keylen,rest)
        if keylen not in '123':
            raise ValueError('22')

        if rest[0] == 'K':
            keyindex = int(rest[1:4],16)
            #print('debug replace_key',keyindex)
            cipher,check = self.KEYS.get(keyindex,(None,None))
            if not cipher:
                raise ValueError('02')
            else:
                rest=rest[4:]
        else:
            cipher=rest[:int(keylen)*16]
            rest=rest[int(keylen)*16:]
        return cipher,rest

    def handle_60(self,data):
        """
         （60/61）   加密一个PIN
        输入指令：2+1+（1A+3H）/16H/32H/48H+2+12+12/18
            2:60
            1:1->64bit,2->128bit,3->192bit
            4:"K"+3位16进制索引号(密钥在密码机中要存放的位置（如：K001）) 16/32/48:用主密钥加密的工作密钥密文
            2:pin块格式 01~06
            12:pin明文要加密的PIN 明文,不足12位填充F。如123456FFFFF
            12/18:账号 12->PIN格式为‘01’ 18->PIN格式为‘04’ 其它PIN格式无此域

        输出结果：2+2+16
            2:61
            2：错误代码，00为正确
            16：加密后的pin模块

            01,03，04正确
            02格式按算法描述因为正确，需确认算法,根据结果反推出填充字符为“E95D0B5B0”,文档为‘987654321’
            05命令填充字符串为随机字符串，因此结果总是不同，但是目前实体机计算过程中算法与稳定说明不同，
                通过结果反算发现为直接将PIN码和填充字符‘F'用PIK加密后生成。如:
                    05:req:6010123456789ABCDEF05123456FFFFFF
                    expect:6100B8C894DF3692B056
            06命令修改完成
       """
        code,keylen = struct.unpack('2s1s',data[:3])
        if code != '60':
            return '6160' #无此命令
        #取得工作密钥
        if data[3] == 'K':
            keyindex = int(data[4:7],16)
            cipher,check = self.KEYS.get(keyindex,(None,None))
            if not cipher:
                return '6102'
            buf=data[:3]+cipher+data[7:]
        else:
            buf=data
        return self.send_recv(buf)

    def handle_62(self,data):
        """
         (62/63)   转换PIN 从一个区域到另一个区域
                   密码机将输入的PIN块的密文用密钥1解密，进行格式转换后，用密钥2加密输出。
        
        需要明确，文档中存在一个附加字段，只有当格式为01或者04时才会存在，但是这个无法确定是原格式还是目标格式
        根据实际结果可得，先取源格式，后取目的格式，当有一个不符合则报错，因此，当均需要附加字段时，只有04-》01,附加为18位命令可成功
        """
        rest=data[2:]
        try:
            keylen1=rest[0]
            cipher1,rest=self.replace_key(rest)
        except ValueError , e:
            return '62'+e[0]
        try:
            keylen2=rest[0]
            cipher2,rest=self.replace_key(rest)
        except ValueError , e:
            return '62'+e[0]
        buf='62'+keylen1+cipher1+keylen2+cipher2+rest
        return self.send_recv(buf)

    def handle_80(self,data):
        """
         (80/81)    3.17 产生MAC（80/81）
                    密码机用指定长度的或指定索引的MAK密钥产生一个指定算法的MAC。
                    注意：
                    XOR MAC支持密钥长度可从单倍长、双倍长到三倍长。
                    ANSI X9.9使用单倍长密钥，本指令不禁止双倍长和三倍长密钥。
                    ANSI X9.19使用双倍长密钥，本指令不禁止单倍长和三倍长密钥。
        输入指令：注：输入裸字符串进行MAC验证

        输出结果：
        """  
        code,mactype,keylen = struct.unpack('2s1s1s',data[:4])
        if code != '80':
            return '8160'#无此命令
        if mactype not in '123':
            return '8123'#MAC模式指示域错
        if keylen not in '123':
            return '8122'#密钥长度与使用模式不符
        
        #取得密钥
        if data[4] == 'K':
            keyindex = int(data[5:8],16)
            cipher,check = self.KEYS.get(keyindex,(None,None))
            if not cipher:
                return '8102'
            buf=data[:4]+cipher+data[8:]
        else:
            buf=data
        return self.send_recv(buf)

    def load(self,fname):
        try:
            self.KEYS=cPickle.load(open(fname))
        except:
            self.KEYS={}

    def save(self):
        try:
            cPickle.dump(self.KEYS,open(self.hsmfile,'w'))
        except IOError:
            print('save hsm to %s failed!'%self.hsmfile)

def loadConfig(fname):
    buf=open(fname).readlines()
    return dict([x.strip().split('=') for x in buf])

if __name__=='__main__':
    conf=loadConfig('emu.conf')
    hsm=Hsm(conf)
    print('HR',hsm.handle('HR'))
    #clear is 8989898989898989,check is F9F4FBD3C9CC8CCC
    print('2A',hsm.handle('2AK1BA157D91AB49FA4701D'))
    print('2C',hsm.handle('2CK1BA'))
    #clear is 1010101010101010,check is 82E13665B4624DF5
    print('2A',hsm.handle('2AK1BB158A1F5BB37961805'))
    print('2C',hsm.handle('2CK1BB'))
    hsm.save()
    print('80',hsm.handle('80130123456789ABCDEFFEDCBA98765432101357902468ABCDEF00200123456789ABCDEF1234')) # '8100FD162D99540B9275'
    print('80',hsm.handle('8011K1BB00200123456789ABCDEF1234')) # '810039B70D348B24E488'
    print('60',hsm.handle('6010123456789ABCDEF05123456FFFFFF')) # random
    print('60',hsm.handle('6010123456789ABCDEF03123456FFFFFF')) # '6100B8C894DF3692B056'
    print('60',hsm.handle('601K1BB03123456FFFFFF')) # '6100F6649CD87D6182D5'
    print('60',hsm.handle('601K1BB01123456FFFFFF012345678901')) # '6100D4011ADB85F14AA6'
    print('62',hsm.handle('6210123456789ABCDEF1FEDCBA987654321001061781BDB51C54F3D5012345678901')) # '6300AE64D1CC36D021A7'
    print('62',hsm.handle('621K1BB1K1BA0106D4011ADB85F14AA6012345678901')) # '630064A9CBC0A30B9FFD'
    print('1E',hsm.handle('1E111C0BE608104E81181D5D44FF720683D0D')) # '1F00B6D1898291A4EF73FCB2E54831F3EC60'
    print('1E',hsm.handle('1E21K1BB1D5D44FF720683D0D')) # '1F0053CBAB404CCA204EF9FA37BBD26F81EB'
    print('1C',hsm.handle('1C1')) 
    print('1C',hsm.handle('1C2KXXX')) 
    print('1C',hsm.handle('1C3K000')) 

    hsm.close()
