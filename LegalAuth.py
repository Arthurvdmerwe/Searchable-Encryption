

class LegalAuthority:

    def __init__(self, identity):
        self.setIdentity(identity)

    def setIdentity(self, identity):
        self.identity = identity

    def getIdentity(self):
        return self.identity

    def setShare(self, share):
        self.share = share

    def getShare(self):
        return self.share

    def Show(self):
        print("Legal Authority: Identity '%s' have share '%s'" % (self.identity, self.share) )