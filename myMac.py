#encoding=utf-8
"""
2013/5/18 humx complete
2013/5/30 humx 修改xor函数，三种MAC算法
"""
import pyDes
import binascii 

class myMac:
    def __init__(self,key,len_data=0,mac_data=''):
        self.len_data = len_data;
        self.data = mac_data 
        self.mactype = [1,2,3]
        self.key = key
        self.mac = ''
        self.hex_mac = ''
        if len(self.key) not in [8,16,24]:
            raise ValueError("Invalid mac key") 

    def __group_xor(self,g1,g2):
        return ''.join(map(lambda x:chr(ord(g1[x[0]])^ord(x[1])),enumerate(g2)))

    def xor(self,a,b):
        return ''.join(map(lambda x,y:chr(ord(x)^ord(y)),a,b))

    def get_mac(self,mactype):
        if mactype not in [1,2,3]:
            raise ValueError("Invalid mac type")
        if mactype == 1:
            return self.XOR_MAC()
        if mactype == 2:
            return self.X99_MAC()
        if mactype == 3:
            return self.X919_MAC()

    def XOR_MAC(self):
        buffer = self.data+'\0'*8
        pre = '\0'*8
        start = 0
        end = len(self.data)
        while(start < end):
            pre = self.xor(pre,buffer[start:start+8])
            start += 8
        if len(self.key) == 8:
            k = pyDes.des(self.key)
        else:
            k = pyDes.triple_des(self.key)

        self.mac = k.encrypt(pre)[:8]
        self.hex_mac = binascii.hexlify(self.mac).upper()
        return self.mac

    def X99_MAC(self):
        if len(self.key) != 8:
            raise ValueError("Invalid mac key. ANSI X9.9 accepts 8 bytes key only")

        buffer = self.data+'\0'*8
        pre = '\0'*8
        start = 0
        end = len(self.data)
        k = pyDes.des(self.key)
        while(start < end):
            pre  = self.xor(pre,buffer[start:start+8])
            pre = k.encrypt(pre)
            start += 8
    
        self.mac = pre[:8]
        self.hex_mac = binascii.hexlify(self.mac).upper()
        return self.mac

    def X919_MAC(self):
        if len(self.key) != 16:
            raise ValueError("Invalid mac key. ANSI X9.19 accepts 16 bytes key only")
        buffer = self.data+'\0'*8
        pre = '\0'*8
        start = 0
        end = len(self.data)
        key_left = self.key[:len(self.key)/2]
        key_right = self.key[len(self.key)/2:]
        lhk = pyDes.des(key_left)
        rhk = pyDes.des(key_right)
        while(start < end):
            pre = self.xor(pre,buffer[start:start+8])
            pre = lhk.encrypt(pre)
            start += 8

        pre = rhk.decrypt(pre)
        pre = lhk.encrypt(pre)
        self.mac = pre[:8]
        self.hex_mac = binascii.hexlify(self.mac).upper()
        return self.mac



if __name__ == "__main__":
    key = binascii.unhexlify("0123456789ABCDEF")
    data =binascii.unhexlify("0123456789ABCDEF1234")
    testMac1 = myMac(key,len(data),data)
    print binascii.hexlify(testMac1.get_mac(1)).upper() 
    print binascii.hexlify(testMac1.get_mac(2)).upper()
    key2 = binascii.unhexlify("0123456789ABCDEFFEDCBA9876543210")
    data2 =binascii.unhexlify("0123456789ABCDEF12345678")
    testMac2 = myMac(key2,len(data2),data2)
    print binascii.hexlify(testMac2.get_mac(3)).upper()  
#    print testMac.X99_MAC()
 #   print testMac.get_mac(2)


        


