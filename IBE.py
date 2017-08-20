
from toolbox.pairinggroup import *
from toolbox.hash_module import *

from schemes.ibenc_bf01 import IBE_BonehFranklin


groupObj = PairingGroup('d224.param', 1024)
ibe = IBE_BonehFranklin(groupObj)

(pk, sk) = ibe.setup()

id = 'ayo@email.com'
key = ibe.extract(sk, id)

m = "hello world!!!!!"
ciphertext = ibe.encrypt(pk, id, m)

msg = ibe.decrypt(pk, key, ciphertext)
assert msg == m, "failed decrypt: \n%s\n%s" % (msg, m)
print("Successful Decryption!!!")
