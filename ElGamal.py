from schemes.pkenc_elgamal85 import ElGamal
from toolbox.eccurve import prime192v2
from SecretShare import Shamir

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
        self.sharing = Shamir(self.sk)
        shares = self.sharing.getShares()
        i =0
        self.masked_shares = []

        for sh in shares:
            self.masked_shares[i] = self.__MaskShare(sh)
            i = i+1
        return self.masked_shares

    def UnMaskShares(self, maskedShares):
        i = 0
        self.unmasked_shares = []
        for sh in maskedShares:
            self.unmasked_shares[i] = self.__UnmaskShare(sh)
            i = i+1


    def RecoverSecret(self):
        self.retrieved_sk = self.sharing.recoverSecret(self.unmasked_shares)
        return self.retrieved_sk

    def __MaskShare(self, message):
        self.msg = message
        size = len(self.msg)
        cipher = self.el.encrypt(self.pk, self.msg)
        return cipher

    def __UnmaskShare(self, cipher):
        m = self.el.decrypt(self.pk, self.sk, cipher)
        assert m == self.msg, "Failed Decryption!!!"
        print("SUCCESSFULLY DECRYPTED!!!")
        return m