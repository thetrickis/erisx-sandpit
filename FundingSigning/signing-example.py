# Python ECDSA signing ... code taken from Eris X documentation.
# Note that this is used only to verify the test harness.
import hashlib
import ecdsa
from ecdsa.util import sigencode_der_canonize 
import base58
import sys

def privateKeyFromPassword( authId, password ):
    return hashlib.pbkdf2_hmac( hash_name='sha256', password=password.encode(), salt=authId.encode(), iterations=100000, dklen=32 )

def signMessage( message, authId, password):
    privateKey = privateKeyFromPassword(authId, password)
    sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
    signature = sk.sign_deterministic(message.encode(), sigencode=sigencode_der_canonize, hashfunc=hashlib.sha256)
    return base58.b58encode(signature).decode('ascii')

# Grab the parameters...
lIdx = 0
lRequestData = ""
lAuthId = ""
lPassword = ""
for lArg in sys.argv:
    if lIdx == 1: 
        lRequestData = lArg
    elif lIdx == 2: 
        lAuthId = lArg
    elif lIdx == 3: 
        lPassword = lArg
    lIdx = lIdx + 1

# Generate the signature
signature = signMessage( lRequestData, lAuthId, lPassword )

# Write it to std-out to conform to the test-harness external process requirement
print(signature)

