#include <string>
#include <iostream>

#include <integer.h>
#include <cryptlib.h>
#include <pwdbased.h>
#include <sha.h>
#include <hex.h>
#include <eccrypto.h>
#include <oids.h>
#include <dsa.h>

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
void helpText()
{
    std::cout << "C++ funding password signing test using CryptoPP" << std::endl;
    std::cout << std::endl;
    std::cout << "signing-example-cpp-cryptopp <RequestData> <AuthId> <Funding Pasword>" << std::endl;
    std::cout << std::endl;
    std::cout << "The application will return the signature on standard-output" << std::endl;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
static const char BASE58TABLE[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string base58encode( unsigned char* aSource, unsigned int aSourceSize )
{
    std::string lResult = "";
    CryptoPP::Integer bn( aSource, aSourceSize );
    CryptoPP::Integer bn0(0L);
    CryptoPP::Integer bn58(58L);
    CryptoPP::Integer dv;
    CryptoPP::Integer rem;
    
    while(bn > bn0)
    {
        CryptoPP::Integer::Divide( rem, dv, bn, bn58 );
        bn = dv;

        char base58char = BASE58TABLE[rem.ConvertToLong()];
        lResult += base58char;
    }

    std::string::iterator pbegin = lResult.begin();
    std::string::iterator pend   = lResult.end();
    while(pbegin < pend) {
        char c = *pbegin;
        *(pbegin++) = *(--pend);
        *pend = c;
    }
    return lResult;
} // base58encode

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
std::string SignMessage( const std::string& aMessage, const std::string& aAuthid, const std::string& aPassword )
{
    // Ecrypt the password, using the salt ==> produce the key
    CryptoPP::byte aResultantKey[ 32 ];
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> lPBKFD2;
    lPBKFD2.DeriveKey(aResultantKey, sizeof(aResultantKey), 0 /* unsused */, (CryptoPP::byte*) aPassword.c_str(), aPassword.length(), (CryptoPP::byte*) aAuthid.c_str(), aAuthid.length(), 100000);

    // Conver the password into a 'big int', so we can 
    CryptoPP::Integer lKeyAsCryptoInteger( aResultantKey, sizeof(aResultantKey) );

    // Create the private key
    CryptoPP::ECDSA_RFC6979<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey lPrivateKey;
    lPrivateKey.Initialize(CryptoPP::ASN1::secp256r1(), lKeyAsCryptoInteger);

    // Prepare the ECDSA signer, with the password key
    CryptoPP::ECDSA_RFC6979<CryptoPP::ECP,CryptoPP::SHA256>::Signer lSigner ( lPrivateKey );

    // Hash the message
    CryptoPP::SHA256 lHash;
    CryptoPP::byte lDigest[ CryptoPP::SHA256::DIGESTSIZE ];
    lHash.CalculateDigest( lDigest, (CryptoPP::byte*) aMessage.c_str(), aMessage.length() );
    
    std::string lHashedMessage;
    CryptoPP::HexEncoder lEncoder;
    lEncoder.Attach( new CryptoPP::StringSink( lHashedMessage ) );
    lEncoder.Put( lDigest, sizeof(lDigest) );
    lEncoder.MessageEnd();

    // Setup array buffer to receive the signature    
    CryptoPP::byte lSignatureBuffer[512];
    CryptoPP::ArraySink* lSignatureBufferWrapper = new CryptoPP::ArraySink( lSignatureBuffer, sizeof(lSignatureBuffer) );

    // Run the signer, producing the output signature in base58 encoded text
    CryptoPP::StringSource lStringSource( lHashedMessage, true, new CryptoPP::SignerFilter( CryptoPP::NullRNG(), lSigner, lSignatureBufferWrapper  ) );

    // I believe this would be required? Convert the sig to DER format; per https://www.cryptopp.com/wiki/DSAConvertSignatureFormat
    unsigned long lDERSigBufferSize = 3+3+3+2+lSignatureBufferWrapper->TotalPutLength();
    CryptoPP::byte lDERSignatureBuffer[512];
    CryptoPP::DSAConvertSignatureFormat(lDERSignatureBuffer, lDERSigBufferSize, CryptoPP::DSA_DER, lSignatureBuffer, lSignatureBufferWrapper->TotalPutLength(), CryptoPP::DSA_P1363 );

    // Finally, encode the signature data in base58
    std::string lSignature = base58encode(lDERSignatureBuffer, lDERSigBufferSize);

    // TODO - things to verify for this cryptopp version (which is currently failing)
    //
    // 1) The message hashing
    // 2) The use of CDSA_RFC6979  ===>  this is a deterministic ECDSA, i was trying to better approximate the python verison
    // 3) The DER conversion
    //
    // I believe the private-key and the base58encoding are fine... and the msg hash should be as well... just not checked.

    return lSignature;
} // SignMessage


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
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
    }

    std::string lFinalSignature = SignMessage( lMsg, lAuthId, lPassword );

    // Output the signature
    std::cout << lFinalSignature << std::endl;

    return 0;
} // main