
from toolbox.pairinggroup import *
from toolbox.hash_module import *

from schemes.ibenc_bf01 import IBE_BonehFranklin


class IBE:

    def __init__(self, identity):
        self.groupObj = PairingGroup('d224.param', 1024)
        self.ibe = IBE_BonehFranklin(self.groupObj)
        (self.pk, self.sk) = self.ibe.setup()


    def setIdentity(self,identity):
        self.id = identity
        self.key = self.ibe.extract(self.sk, self.id)

    def encrypt(self, message):
        self.m = message
        ciphertext = self.ibe.encrypt(self.pk, self.id, message)
        return ciphertext

    def decrypt(self, ciphertext):
        msg = self.ibe.decrypt(self.pk, self.key, ciphertext)
        assert msg == self.m, "failed decrypt: \n%s\n%s" % (msg, self.m)
        print("Successful Decryption!!!")
        return msg
