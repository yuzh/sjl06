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

2013/8/6 重构代码，通过实体加密机实现指令功能
"""
import cPickle
import pyDes
import binascii
import struct
import random
import socket

class Hsm:
    def __init__(self,conf):
        self.hsmfile=conf.get('hsm_data','9.249.keys')
        self.load(self.hsmfile)
        hsm_ip=conf.get('real_hsm_ip','10.112.18.22')
        hsm_port=int(conf.get('real_hsm_port','10010'))
        self.hsm_prefix=conf.get('hsm_prefix','001001')
        self.reserve_index=int(conf.get('reserve_index','4095'))

        try:
            self.hsm_sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.hsm_sock.connect((hsm_ip,hsm_port))
        except socket.error as msg:
            self.hsm_sock=None
            print('connect %s:%d error!'%(hsm_ip,hsm_port),msg)

        self.FuncMap={}
        # 查找Hsm类中所有形如handle_XX的函数，注册到函数映射表中
        funcs=[x for x in dir(Hsm) \
            if callable(getattr(self,x)) and x[:7]=='handle_']
        # {'XX':handle_XX}
        for f in funcs:
            self.FuncMap[f[-2:]]=getattr(self,f)

    def close(self):
        if self.hsm_sock:
            print('close the socket')
            self.hsm_sock.close()

    def send(self,data):
        buf=self.hsm_prefix+data
        buf=struct.pack('>h',len(buf))+buf
        self.hsm_sock.send(buf)
        pkglen,pkg=self.recv()
        return pkg

    def recv(self):
        buf=self.hsm_sock.recv(8192)
        pkglen=struct.unpack('>h',buf[:2])[0]
        pkg=buf[2:2+pkglen]
        if self.hsm_prefix:
            pf_len=len(self.hsm_prefix)
            pkg=pkg[pf_len+2:]
            pkglen-=pf_len+2
        return (pkglen,pkg)

    def handle(self,data):
        code=data[:2]
        if code in ('HR','2A','2C','1E','60','62','63','80'):
            return self.FuncMap.get(data[:2])(data)
        else:
            print('Invalid request %s'%(data))
            return None

    def handle_HR(self,data):
        return self.send('HR')

    def even_chk_part(self,ch):#奇校验部分
     return ch^(1-[y>0 and 1 or 0 for y in [ch&x for x in (128,64,32,16,8,4,2,1)]].count(1)%2)

    def even_chk(self,chk):#奇校验,16进制未展开，/OX形式
        return ''.join([chr(self.even_chk_part(ord(x))) for x in chk])

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
        code,flag1,keylen = struct.unpack('2s1s1s',data[:4])
        currentend = 4
        if code != '1E':
            return '1F60' #无此命令
        if flag1 not in '12':
            return '1F77' #非法字符
        if keylen not in '123':
            return '1F77' #非法字符

        code2,hexindex = struct.unpack('1s3s',data[currentend:currentend+4])

        #得到KEK干净的密钥
        if code2 == 'K':#输入索引
            currentend = currentend+4
            try:#得到KEK密钥索引
                keyindex=int(hexindex,16)
                if keyindex<1 or keyindex>4096:
                    raise ValueError
            except ValueError:
                return '1F33' #密钥索引错

            KEK=self.getkey(keyindex)#取出KEK密钥
            if(len(KEK)!=int(keylen)*8):
                return '1F22'#密钥长度与使用模式不符
        else:#输入WK加密的KEK
            KEK_cipher = binascii.unhexlify(data[currentend:currentend+16*int(keylen)])
            k = pyDes.triple_des(self.HSM['lmk'])#加密机主密钥
            KEK = k.decrypt(KEK_cipher)#解密KEK
            currentend = currentend+16*int(keylen)
        
        KEK = self.even_chk(KEK)#奇校验KEK

        #取得加密的WK
        keylen2 = data[currentend]#密文长度
        currentend = currentend+1
        if keylen2 not in '123':
            return '1F77' #非法字符

        cipher = binascii.unhexlify(data[currentend:currentend+16*int(keylen2)])#取出主密钥加密后的密文
        currentend = currentend+16*int(keylen2)

        if flag1 == '1':#MK加密->KEK加密 输入KEK索引或者KEK密钥值
            old_key = self.HSM['lmk']
            old_key_len = '3'
            new_key = KEK
            new_key_len = keylen
        else:#KEK加密->MK加密 输入MK加密KEK密钥或者KEK索引
            old_key = KEK
            old_key_len = keylen
            new_key = self.HSM['lmk']
            new_key_len = '3'

        #解密加密后的WK
        if old_key_len == '1':
            k = pyDes.des(old_key)
        else:
            k = pyDes.triple_des(old_key)    
        clear = k.decrypt(cipher)#解密KEK加密密文，得到干净WK
        
        clear = self.even_chk(clear)#奇校验
        
        left = data[currentend:]#存储新密钥
        if left != '':
            if left[0]!='K':
                return '1F60' #无此命令
            try:#得到存储密钥索引
                keyindex2=int(left[1:4],16)
                if keyindex2<1 or keyindex2>4096:
                    raise ValueError
            except ValueError:
                return '1F33' #密钥索引错
            self.setkey(keyindex2,clear)

        #计算结果
        if new_key_len == '1':#新密钥K密钥加密WK
            wk = pyDes.des(new_key)
        else:
            wk = pyDes.triple_des(new_key)
        message = wk.encrypt(clear)#使用KEK加密后的WK密文

        if keylen2 == '1':#WK校验值
            wk2 = pyDes.des(clear)
        else:
            wk2 = pyDes.triple_des(clear)
        check=wk2.encrypt('\x00'*8)

        result='1F00'+binascii.hexlify(message).upper()+binascii.hexlify(check).upper()

        return result        

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
            if keyindex<1 or keyindex>4096:
                raise ValueError
        except ValueError:
            return '2B33' #密钥索引错
        if keylen not in '123':
            return '2B22' #密钥长度与使用模式不符
        
        cipher=data[7:]
        buf=code+'%03X'%(self.reserve_index)+keylen+cipher
        pkg=self.send(buf)
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
            hexindex = data[4:7]
            keyindex = int(hexindex,16)
            next_field = 7
            if keyindex<1 or keyindex>4096:
                return '6133' #密钥索引错
            working_key = self.getkey(keyindex) 
        else:
            if keylen not in '123':
                return '6122'#密钥长度与使用模式不符
            hex_cipher_len = int(keylen)*16
            cipher = binascii.unhexlify(data[3:3+hex_cipher_len])
            if len(cipher) != int(keylen)*8:
                return '6122'#密钥长度与使用模式不符
            next_field = 3+hex_cipher_len
            k = pyDes.triple_des(self.HSM['lmk']) 
            working_key = k.decrypt(cipher)

        if(keylen == '1'):
            pik = pyDes.des(working_key)
        else:
            pik = pyDes.triple_des(working_key)

        pin_fmt = data[next_field:next_field+2]
        next_field += 2
        pin_field = data[next_field:next_field+12] 
        next_field += 12
        pin_code = filter(lambda x: x<'F',pin_field)        
        pin_account = ''

        if not pin_fmt in ['01','02','03','04','05','06']:
            return '6128' #PIN 格式错误
        else:
            if pin_fmt == '01':
                pin_account =data[next_field:]
                if len(pin_account) != 12:
                    return '6128' #PIN 格式错误
            if pin_fmt == '04':
                pin_account = data[next_field:]
                if len(pin_account) != 18:
                    return '6128' #PIN 格式错误
        
        pin = myPin(pin_code,pin_account,pin_fmt)
        try: 
            pin_block = pin.format()
        except ValueError:
            return '6128'#PIN 格式错误
        encrypted_pin =binascii.hexlify(pik.encrypt(binascii.unhexlify(pin_block))).upper() 
        result = '6100'+encrypted_pin
        decrypted_pin = pik.decrypt(binascii.unhexlify(encrypted_pin))
        return result

    def handle_62(self,data):
        """
         (62/63)   转换PIN 从一个区域到另一个区域
                   密码机将输入的PIN块的密文用密钥1解密，进行格式转换后，用密钥2加密输出。
        
        需要明确，文档中存在一个附加字段，只有当格式为01或者04时才会存在，但是这个无法确定是原格式还是目标格式
        根据实际结果可得，先取源格式，后取目的格式，当有一个不符合则报错，因此，当均需要附加字段时，只有04-》01,附加为18位命令可成功
        """
        code = data[:2]
        if code != '62':
            return '6362'

        keylen_1 = data[2]
        if data[3] == 'K':
            hexindex = data[4:7]
            keyindex = int(hexindex,16)
            next_field = 7
            if keyindex<1 or keyindex>4096:
                return '6333' #密钥索引错
            wk_1 = self.getkey(keyindex) #wk_1 工作密钥1
        else:
            if keylen_1 not in '123':
                return '6322'#密钥长度与使用模式不符
            hex_cipher_len = int(keylen_1)*16
            cipher = binascii.unhexlify(data[3:3+hex_cipher_len])
            if len(cipher) != int(keylen_1)*8:
                return '6322'#密钥长度与使用模式不符
            next_field = 3+hex_cipher_len
            k = pyDes.triple_des(self.HSM['lmk']) 
            wk_1 = k.decrypt(cipher)

        keylen_2 = data[next_field]
        next_field += 1
        if data[next_field] == 'K':
            next_field += 1
            hexindex = data[next_field:next_field+3]
            keyindex = int(hexindex,16)
            next_field += 3 
            if keyindex<1 or keyindex>4096:
                return '6333' #密钥索引错
            wk_2 = self.getkey(keyidnex) #wk_1 工作密钥1
        else:
            if keylen_2 not in '123':
                return '6322'#密钥长度与使用模式不符
            hex_cipher_len = int(keylen_2)*16
            cipher = binascii.unhexlify(data[next_field:next_field+hex_cipher_len])
            if len(cipher) != int(keylen_2)*8:
                return '6322'#密钥长度与使用模式不符
            next_field += hex_cipher_len
            k = pyDes.triple_des(self.HSM['lmk']) 
            wk_2 = k.decrypt(cipher)
       

        src_pin_fmt,dst_pin_fmt,hex_cipher_pin = struct.unpack('2s2s16s',data[next_field:next_field+20])

        next_field += 20
        if not src_pin_fmt in ['01','02','03','04','05','06']:
            return '6328' #PIN 格式错误
        if not dst_pin_fmt in ['01','02','03','04','05','06']:
            return '6328' #PIN 格式错误


        pin_src_account = ''
        if src_pin_fmt == '01':
            pin_src_account =data[next_field:]
            if len(pin_src_account) > 12:
                return '6328' #PIN 格式错误
            if len(pin_src_account) < 12:
                    return '6361' #消息太短
        if src_pin_fmt == '04':
            pin_src_account = data[next_field:]
            if len(pin_src_account) < 18:
                return '6361' #消息太短
            if len(pin_src_account) > 18:
                return '6328' #PIN 格式错误

        pin_dst_account=''
        if dst_pin_fmt == '01':
            pin_dst_account =data[next_field:]
            if len(pin_dst_account)!=12:
                if len(pin_dst_account) < 12:
                    return '6361' #消息太短
                if len(pin_dst_account) == 18 and src_pin_fmt =='04':
                    pin_des_account = data[next_field:next_field+12]
                else:
                    return '6328'
        if dst_pin_fmt == '04':
            pin_dst_account = data[next_field:]
            if len(pin_dst_account) < 18:
                return '6361' #消息太短
            if len(pin_dst_account) > 18:
                return '6328' #PIN 格式错误

        #用密钥1解密PIN块密文
        if(keylen_1 == '1'):
            k1 = pyDes.des(wk_1)
        else:
            k1 = pyDes.triple_des(wk_1)
        pin_uncipher = binascii.hexlify(k1.decrypt(binascii.unhexlify(hex_cipher_pin))).upper()
        
        #转换pin格式
        pin = myPin()
        #利用源格式解码
        pin_code = pin.de_format(src_pin_fmt,pin_uncipher,pin_src_account)

        #利用目的格式编码
        converted_pin = myPin(pin_code,pin_dst_account,dst_pin_fmt)
        pin_formatted = converted_pin.format()

        #用密钥2加密格式转换后的pin
        if keylen_2 == '1':
            k2 = pyDes.des(wk_2)
        else:
            k2 = pyDes.triple_des(wk_2)
        pin_result = k2.encrypt(binascii.unhexlify(pin_formatted))
        result = '6300'+binascii.hexlify(pin_result).upper()
        return result

    def handle_68(self,data):
        """
         (68/69)   解密一个PIN
        输入指令：

        输出结果：
        """       
        code,keylen = struct.unpack('2s1s',data[:3])
        if code != '68':
            return '6960' #无此命令
        if data[3] == 'K':
            hexindex = data[4:7]
            keyindex = int(hexindex,16)
            next_field = 7
            if keyindex<1 or keyindex>4096:
                return '6933' #密钥索引错
            working_key = self.getkey(keyindex) 
        else:
            if keylen not in '123':
                return '6922'#密钥长度与使用模式不符
            hex_cipher_len = int(keylen)*16
            cipher = binascii.unhexlify(data[3:3+hex_cipher_len])
            if len(cipher) != int(keylen)*8:
                return '6922'#密钥长度与使用模式不符
            next_field = 3+hex_cipher_len
            k = pyDes.triple_des(self.HSM['lmk']) 
            working_key = k.decrypt(cipher)

        pin_fmt = data[next_field:next_field+2]
        next_field += 2
        pin_cipher = data[next_field:next_field+16] 
        next_field += 16

        pin_account = ''

        if not pin_fmt in ['01','02','03','04','05','06']:
            return '6128' #PIN 格式错误
        else:
            if pin_fmt == '01':
                pin_account =data[next_field:]
                if len(pin_account) != 12:
                    return '6928' #PIN 格式错误
            if pin_fmt == '04':
                pin_account = data[next_field:]
                if len(pin_account) != 18:
                    return '6928' #PIN 格式错误
        if keylen == '1':
            k = pyDes.des(working_key)
        else:
            k = pyDes.triple_des(working_key)
        pin_block = binascii.hexlify(k.decrypt(binascii.unhexlify(pin_cipher))).upper()
        pin = myPin()
        pin_code = pin.de_format(pin_fmt,pin_block,pin_account)

        pin_code = pin_code + (12-len(pin_code))*'F'
        result = '6900%s'%(pin_code)
        return result

    def handle_80(self,data):#待完成
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
        return self.send(buf)

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
    print('2A',hsm.handle('2AK1BB157D91AB49FA4701D'))
    print('2C',hsm.handle('2CK1BB'))
    #clear is 1010101010101010,check is 82E13665B4624DF5
    print('2A',hsm.handle('2AK1BB158A1F5BB37961805'))
    print('2C',hsm.handle('2CK1BB'))
    hsm.save()
    print('80',hsm.handle('80130123456789ABCDEFFEDCBA98765432101357902468ABCDEF00200123456789ABCDEF1234')) # '8100FD162D99540B9275'
    print('80',hsm.handle('8011K1BB00200123456789ABCDEF1234')) # '810039B70D348B24E488'
    hsm.close()
