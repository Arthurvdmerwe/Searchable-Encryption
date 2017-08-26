from schemes.pkenc_elgamal85 import ElGamal
from toolbox.eccurve import prime192v2
from SecretShare import Shamir
import time
from toolbox.ecgroup import *

class Threshold_ElGamal:

    def __init__(self):


        self.el = ElGamal(ecc, prime192v2)

    def KeyShareGen(self):
        (pk, sk) = self.el.keygen()
        self.pk = pk
        self.sk = sk

    #def getPK(self):
    #    return self.pk

    #def getSK(self):
    #    return self.sk

    def MaskShares(self):

        self.partial_sk = str(self.sk['x'])

        self.sharing = Shamir(int(self.partial_sk))
        self.shares = self.sharing.getShares()
        i =0
        self.masked_shares = []

        #for sh in shares:
        #    self.masked_shares[i] = self.__MaskShare(sh)
        #    i = i+1
        #return self.masked_shares
        return self.shares

    def UnMaskShares(self, maskedShares):
        #i = 0
        #self.unmasked_shares = []
        #for sh in maskedShares:
        #    self.unmasked_shares[i] = self.__UnmaskShare(sh)
        #    i = i+1
        return self.shares

    def RecoverSecret(self):
        self.retrieved_sk = self.sharing.recoverSecret(self.shares)
        return self.retrieved_sk

    def __MaskShare(self, message):
        print ("Masking Share '%s'" % message)
        self.msg = message
        #size = len(self.msg)
        cipher = self.el.encrypt(self.pk, str(self.msg).encode('utf-8'))
        return cipher

    def __UnmaskShare(self, cipher):
        m = self.el.decrypt(self.pk, self.sk, cipher)
        assert m == self.msg, "Failed Decryption!!!"
        print("SUCCESSFULLY DECRYPTED!!!")
        return m

if __name__ == '__main__':

    #Test El Gamal Threshold
    time1 = time.time()
    el = Threshold_ElGamal()
    time2 = time.time()
    print ('%s function took %0.3f ms' % ("Initiating Paramaters", (time2-time1)*1000.0))

    time3 = time.time()
    el.KeyShareGen()
    time4 = time.time()
    print ('%s function took %0.3f ms' % ("Generating Keys", (time4-time3)*1000.0))

    print ("Generate Keys ")
    print ("Secret Key '%s'" % el.sk)
    print ("Public Key '%s'" %el.pk)

    print ("Generate Shares")

    time5= time.time()
    shares = el.MaskShares()
    time6= time.time()
    print ('%s function took %0.3f ms' % ("Masking Shares", (time6-time5)*1000.0))

    print('UnMasking Shares')
    time7= time.time()
    el.UnMaskShares(shares)
    time8= time.time()
    print ('%s function took %0.3f ms' % ("UNMasking Shares", (time8-time7)*1000.0))

    time9= time.time()
    el.RecoverSecret()
    time10= time.time()
    print ('%s function took %0.3f ms' % ("Recovering Secret", (time10 - time9)*1000.0))

