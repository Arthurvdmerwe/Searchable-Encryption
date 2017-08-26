
from toolbox.pairinggroup import *
from toolbox.hash_module import *
import time
from schemes.ibenc_bf01 import IBE_BonehFranklin


class IBE:

    def __init__(self):

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


if __name__ == '__main__':
    time1 = time.time()
    ibe = IBE()
    time2 = time.time()
    print('%s function took %0.3f ms' % ("Initiating IBE", (time2 - time1) * 1000))

    ibe2 = IBE()

    ibe2.setIdentity('peter@herts.ac.uk')

    time3 = time.time()
    ibe.setIdentity('arthur.vandermerwe@westpac.com.au')
    time4 = time.time()
    print('%s function took %0.3f ms' % ("Setting Identity", (time4 - time3) * 1000))

    time5 = time.time()
    ciphertext = ibe.encrypt('message')
    time6 = time.time()
    print('%s function took %0.3f ms' % ("Encryption", (time6 - time5) * 1000))


    ciphertext2 = ibe2.encrypt('message')

    time7 = time.time()
    ibe.decrypt(ciphertext)
    time8 = time.time()
    print('%s function took %0.3f ms' % ("Decryption", (time8 - time7) * 1000))

    #ibe2.decrypt(ciphertext)