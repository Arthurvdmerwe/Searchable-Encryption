

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

if __name__ == '__main__':

#Test Secret Sharing

    sh = Shamir(10519865178556314507372829289402446664989949293459045562116909548466503245062007515340903772742587227490252706716592603738153226430667106582098446163222092298895072223005902735406151155098458263113996593288431704943669561903201783705478080949723622879177900831232543138340985242764836383559333313982615832160)
    shares = sh.getShares()
    sh.recoverSecret(shares)
