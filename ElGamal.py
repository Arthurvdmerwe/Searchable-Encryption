from toolbox.integergroup import IntegerGroupQ
from toolbox.ecgroup import *
from toolbox.PKEnc import PKEnc
from schemes.pkenc_elgamal85 import ElGamal
from toolbox.eccurve import prime192v2

class Threshold_ElGamal:

    def __init__(self):
        self.el = ElGamal(ecc, prime192v2)

    def keygen(self):
        (pk, sk) = self.el.keygen()
        self.pk = pk
        self.sk = sk

    def getPK(self):
        return self.pk

    def getSK(self):
        return self.sk

    def encrypt(self, message):
        self.msg = message
        size = len(self.msg)
        cipher = self.el.encrypt(self.pk, self.msg)
        return cipher

    def decrypt(self, cipher):
        m = self.el.decrypt(self.pk, self.sk, cipher)
        assert m == self.msg, "Failed Decryption!!!"
        print("SUCCESSFULLY DECRYPTED!!!")
        return m