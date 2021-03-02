#include <string>
#include <iostream>
#include <iomanip>
#include <cstring>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

const int sKeySize = 32; // 256 bit key

void helpText()
{
    std::cout << "C++ funding password signing test using openssl" << std::endl;
    std::cout << std::endl;
    std::cout << "signing-example-cpp-openssl <RequestData> <AuthId> <Funding Pasword>" << std::endl;
    std::cout << std::endl;
    std::cout << "The application will return the signature on standard-output" << std::endl;
}

// A borrowed base58 encode
static const char BASE58TABLE[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string base58encode( unsigned char* aSource, unsigned int aSourceSize )
{
    std::string result = "";
    BN_CTX * bnctx = BN_CTX_new();
    BIGNUM * bn = BN_new();
    BIGNUM * bn0= BN_new();
    BIGNUM * bn58=BN_new();
    BIGNUM * dv = BN_new();
    BIGNUM * rem= BN_new();

    BN_bin2bn(aSource, aSourceSize, bn );
    BN_hex2bn(&bn58, "3a");//58
    BN_hex2bn(&bn0,"0");

    while(BN_cmp(bn, bn0)>0){
        BN_div(dv, rem, bn, bn58, bnctx);
        BN_copy(bn, dv);
        char base58char = BASE58TABLE[BN_get_word(rem)];
        result += base58char;
    }

    std::string::iterator pbegin = result.begin();
    std::string::iterator pend   = result.end();
    while(pbegin < pend) {
        char c = *pbegin;
        *(pbegin++) = *(--pend);
        *pend = c;
    }
    return result;
} // base58encode


// Return error-codes to track staged errors
int main( int argc, char** argv )
{
    if ( argc != 4 ) { helpText(); return 1; }

    std::string lPassword = "";
    std::string lAuthId = "";
    std::string lMsg = "";

    for ( int i=0; i<argc; i++ )
    {
        std::string lArg = argv[i];
        if ( lArg == "-h" || lArg == "--help" ) { helpText(); return 1; }

        switch ( i )
        {
            case 1:
              lMsg = lArg;
              break;

            case 2:
              lAuthId = lArg;
              break;

            case 3:
              lPassword = lArg;
              break;
        }
    } // for each arg

    // Create the private key from the password and auth-id salt
    unsigned char lPrivateKeyFromPassword[sKeySize];
    int lRetval = PKCS5_PBKDF2_HMAC(lPassword.c_str(), lPassword.length(), (unsigned char*) lAuthId.c_str(), lAuthId.length(), 100000, EVP_sha256(), sKeySize, lPrivateKeyFromPassword);
    if ( lRetval == 0 ) return 2;

    // Convert the private-key into a big-number for the EC_KEY setup
    BIGNUM* lPrivateKeyasBigNum = BN_bin2bn( lPrivateKeyFromPassword, sKeySize, NULL );

    // Set the key type
    EC_KEY *lEcKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (lEcKey == NULL) return 3;

    if ( EC_KEY_set_private_key(lEcKey, lPrivateKeyasBigNum) != 1 ) return 4;

    // Setting the public key for verification. (unnecessary for actual signing)
    //
    // // Context for big-number ops
    // BN_CTX* lBnCtx = BN_CTX_new();
    // BN_CTX_start(lBnCtx);

    // // Set the public key
    // const EC_GROUP* lGroup = EC_KEY_get0_group(lEcKey);
    // EC_POINT* lPub = EC_POINT_new(lGroup);
    // EC_POINT_mul(lGroup, lPub, lPrivateKeyasBigNum, NULL, NULL, lBnCtx);
    // EC_KEY_set_public_key(lEcKey, lPub);

    // // verify the key
    // if ( EC_KEY_check_key( lEcKey ) != 1 ) return 5;

    // Hash the message.
    unsigned char lShaMsg[sKeySize];
    EVP_MD_CTX* lCtx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(lCtx, EVP_sha256(), NULL);
    EVP_DigestUpdate(lCtx, lMsg.c_str(), lMsg.length() );
    EVP_DigestFinal_ex(lCtx, lShaMsg, NULL);
    EVP_MD_CTX_destroy(lCtx);

    // Sign the message    
    ECDSA_SIG* lSignature = ECDSA_do_sign( lShaMsg, sKeySize, lEcKey );
    if ( lSignature == NULL ) return 6;

    // convert the signature to DER format
    unsigned int lDERSignatureSize = i2d_ECDSA_SIG( lSignature, NULL );
    unsigned char *lDERSignatureData = new unsigned char[lDERSignatureSize];
    unsigned char *p = lDERSignatureData;
    i2d_ECDSA_SIG( lSignature, &p );

    // Encode the signature using Base58 encoding.
    std::string lSignatureInBase58 = base58encode( lDERSignatureData, lDERSignatureSize );

    // Output the signature to stdout
    std::cout << lSignatureInBase58 << std::endl;

    // some cleanup (check the ops above... more cleanup likely required for a production app) 
    EC_KEY_free(lEcKey);
    if (lPrivateKeyasBigNum!= NULL) BN_free(lPrivateKeyasBigNum);

    return 0;
} // main