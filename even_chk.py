import binascii
f_keyodd=lambda key:''.join(\
	map(lambda x:'%02X'%(x),\
	map(lambda ch:ch^(1-tuple(map(lambda y:(y>0) and 1 or 0 ,\
	map(lambda x:x&ch,(128,64,32,16,8,4,2,1)))).count(1)%2),\
	binascii.unhexlify(key)\
	))).upper()

zmk='3016745ab289efcdbadcfe0325476981'
print(__import__('os').linesep.join((zmk,f_keyodd(zmk))))
