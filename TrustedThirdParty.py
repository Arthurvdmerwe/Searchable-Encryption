from ElGamal import Threshold_ElGamal


class TrustedThirdParty:

    def __init__(self):
        self.threshold = Threshold_ElGamal()


        self.authorities = []
        self.authorities_share_map = {}

    def generateShares(self):
        self.threshold.KeyShareGen()
        self.shares = self.threshold.MaskShares()
        return self.shares

    def registerAuthority(self, identity):
        self.authorities.append(identity)


    def combineShares(self, shares):
        secret = self.threshold.UnMaskShares(shares)
        return secret
