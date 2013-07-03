def f(ch):
  return ch^(1-[y>0 and 1 or 0 for y in [ch&x for x in (128,64,32,16,8,4,2,1)]].count(1)%2)

  
print ''.join([chr(f(ord(x))) for x in 'the key clear'])
