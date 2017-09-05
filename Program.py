from toolbox.pairinggroup import PairingGroup,pair
from TrustedThirdParty import TrustedThirdParty
from LegalAuth import LegalAuthority
from IBE import  IBE
from PKS import PKS
import time

if __name__ == '__main__':
    time27 = time.time()
    time1 = time.time()
    trusted_party = TrustedThirdParty()
    time2 = time.time()
    print('%s function took %0.3f ms' % ("Initiating TrustedThirdParty", (time2 - time1) * 1000))

    time3 = time.time()
    # Initiate Legal Authorities
    legal_auth1 = LegalAuthority('arthur.vandermerwe@westpac.com.au')
    legal_auth2 = LegalAuthority('arthur@cashpoint.com.au')
    legal_auth3 = LegalAuthority('arthur@switchLink.com.au')
    time4 = time.time()
    print('%s function took %0.3f ms' % ("Initiating Legal Authorities", (time4 - time3) * 1000))

    time5 = time.time()
    #register authorities with third parties
    identity_encryption1 = IBE()
    identity_encryption2 = IBE()
    identity_encryption3 = IBE()
    time6 = time.time()
    print('%s function took %0.3f ms' % ("Initiating IBE", (time6 - time5) * 1000))

    time7 = time.time()
    identity_encryption1.setIdentity(legal_auth1.getIdentity())
    identity_encryption2.setIdentity(legal_auth2.getIdentity())
    identity_encryption3.setIdentity(legal_auth3.getIdentity())
    time8 = time.time()
    print('%s function took %0.3f ms' % ("Set Identities in IBE", (time8 - time7) * 1000))



    #generate shares
    time9 = time.time()
    shares = str(trusted_party.generateShares())
    time10 = time.time()
    print('%s function took %0.3f ms' % ("Generating Shares", (time10 - time9) * 1000))

    #encrypt shares with identity
    time11 = time.time()
    legal_auth1.setShare(identity_encryption1.encrypt(shares[1]))
    legal_auth2.setShare(identity_encryption2.encrypt(shares[2]))
    legal_auth3.setShare(identity_encryption3.encrypt(shares[3]))
    time12 = time.time()
    print('%s function took %0.3f ms' % ("Encrypting Shares", (time12 - time11) * 1000))

    #look at the identities
    legal_auth1.Show()
    legal_auth2.Show()
    legal_auth3.Show()

    #decrypt the shares
    time13 = time.time()
    decrypted_shares = []
    decrypted_shares.insert(1, identity_encryption1.decrypt(legal_auth1.getShare()))
    decrypted_shares.insert(2, identity_encryption2.decrypt(legal_auth2.getShare()))
    decrypted_shares.insert(3, identity_encryption3.decrypt(legal_auth3.getShare()))
    time14 = time.time()
    print('%s function took %0.3f ms' % ("Decrypting Shares", (time14 - time13) * 1000))

    #recover the secret
    time15 = time.time()
    recovered_secret = trusted_party.combineShares(decrypted_shares)
    print("Recovered Secret %s" % recovered_secret[0])
    time16 = time.time()
    print('%s function took %0.3f ms' % ("Recovering Secret", (time16 - time15) * 1000))

    #searchable encryption
    time17 = time.time()
    group = PairingGroup('SS512')
    peks = PKS(group)
    time18 = time.time()
    print('%s function took %0.3f ms' % ("Initiating searchable encryption", (time18 - time17) * 1000))

    KEYWORD1 = "fishing"
    KEYWORD2 = "shower"
    time19 = time.time()
    pub = peks.KeyGen()
    time20 = time.time()
    print('%s function took %0.3f ms' % ("Searchable Encryption, KeyGen", (time20 - time19) * 1000))

    time21 = time.time()
    pek = peks.PEKS(KEYWORD1)
    time22 = time.time()
    print('%s function took %0.3f ms' % ("Searchable Encryption, PEKS", (time22 - time21) * 1000))
    #trapdoor2 = peks.PEKS(KEYWORD2)

    time23 = time.time()
    trapdoor = peks.Trapdoor(KEYWORD1)
    time24 = time.time()
    print('%s function took %0.3f ms' % ("Searchable Encryption, Trapdoor", (time24 - time23) * 1000))

    time25 = time.time()
    print(peks.Test(pub, trapdoor))
    time26 = time.time()
    print('%s function took %0.3f ms' % ("Searchable Encryption, Test", (time26 - time25) * 1000))
    time28 = time.time()
    print('%s function took %0.3f ms' % ("TOTAL TIME", (time28 - time27) * 1000))
    #peks.Test(pub, trapdoor2)