
from TrustedThirdParty import TrustedThirdParty
from LegalAuth import LegalAuthority
from IBE import  IBE

if __name__ == '__main__':


    trusted_party = TrustedThirdParty()

    # Initiate Legal Authorities
    legal_auth1 = LegalAuthority('arthur.vandermerwe@westpac.com.au')
    legal_auth2 = LegalAuthority('arthur@cashpoint.com.au')
    legal_auth3 = LegalAuthority('arthur@switchLink.com.au')

    #register authorities with third parties
    identity_encryption1 = IBE()
    identity_encryption2 = IBE()
    identity_encryption3 = IBE()

    identity_encryption1.setIdentity(legal_auth1.getIdentity())
    identity_encryption2.setIdentity(legal_auth2.getIdentity())
    identity_encryption3.setIdentity(legal_auth3.getIdentity())




    #generate shares
    shares = str(trusted_party.generateShares())

    #encrypt shares with identity
    legal_auth1.setShare(identity_encryption1.encrypt(shares[1]))
    legal_auth2.setShare(identity_encryption2.encrypt(shares[2]))
    legal_auth3.setShare(identity_encryption3.encrypt(shares[3]))

    #look at the identities
    legal_auth1.Show()
    legal_auth2.Show()
    legal_auth3.Show()

    #decrypt the shares
    decrypted_shares = []
    decrypted_shares.insert(1, identity_encryption1.decrypt(legal_auth1.getShare()))
    decrypted_shares.insert(2, identity_encryption2.decrypt(legal_auth2.getShare()))
    decrypted_shares.insert(3, identity_encryption3.decrypt(legal_auth3.getShare()))

    recovered_secret = trusted_party.combineShares(decrypted_shares)
    print("Recovered Secret %s" % recovered_secret[0])