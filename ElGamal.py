from toolbox.integergroup import IntegerGroupQ
from toolbox.ecgroup import *
from toolbox.PKEnc import PKEnc
from schemes.pkenc_elgamal85 import ElGamal
from toolbox.eccurve import prime192v2



el = ElGamal(ecc, prime192v2)

(pk, sk) = el.keygen()

msg = b"hello world!"
size = len(msg)
cipher1 = el.encrypt(pk, msg)

m = el.decrypt(pk, sk, cipher1)
assert m == msg, "Failed Decryption!!!"
print("SUCCESSFULLY DECRYPTED!!!")