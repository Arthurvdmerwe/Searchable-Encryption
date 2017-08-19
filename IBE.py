
from toolbox.pairinggroup import PairingGroup,ZR,GT
from schemes.ibenc_adapt_identityhash import HashIDAdapter
from schemes.ibenc_bb03 import IBE_BB04, IBEnc
from schemes.ibenc_waters05 import IBE_N04


groupObj = PairingGroup('SS512',secparam=512)
ibe = IBE_BB04(groupObj)
(params, mk) = ibe.setup()

# represents public identity
kID = groupObj.random(ZR)
key = ibe.extract(mk, kID)

M = groupObj.random(GT)
cipher = ibe.encrypt(params, kID, M)
m = ibe.decrypt(params, key, cipher)

assert m == M, "FAILED Decryption!"
print("Successful Decryption!! M => '%s'" % m)
