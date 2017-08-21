

from toolbox.secretshare import SecretShare
from toolbox.pairinggroup import PairingGroup,ZR

class Shamir:

    def __init__(self, secret):
        self.k = 3
        self.n = 4
        self.group = PairingGroup('SS512')
        self.s = SecretShare(self.group, False)
        self.sec = secret

    def getShares(self):
        shares = self.s.genShares(self.sec, self.k, self.n)
        print('\nShares: %s' % shares)
        self.K = shares[0]
        print('\nOriginal secret: %s' % self.K)
        return shares

    def recoverSecret(self, shares):
        y = {self.group.init(ZR, 1): shares[1], self.group.init(ZR, 2): shares[2], self.group.init(ZR, 3): shares[3]}
        secret = self.s.recoverSecret(y)
        assert self.K == secret, "Could not recover the secret!"
        print("Successfully recovered secret: ", secret)
