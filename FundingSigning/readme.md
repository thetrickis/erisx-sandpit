# Funding Signing
Simple test harness to verify message signing for erisX funding password; very rough and ready for prototyping.

Harness is written in javascript (see drive-funding-api.js), to handle REST calls - javascript calls out to external process to sign the request_data.
(Note: requires nodejs)

Harness executes with runtest-against-erisx.sh, passing in the api key/secret/fund-password and the executable for the external signing. 

## Signing Versions
It currently has 3 versions it will run through:

1/ python - as a proof of the harness, using the erisX provided code;
2/ openssl - C++ signing, using the very standard openssl crypto library.
3/ cryptopp - (work in progress) C++ signing, using the crypo++ library.

## Dependencies:

OpenSSL - will need openssl installed for development; and the include and link paths will need to be set in the Makefile
Cypto++ - will need to be downloaded (GitHub) and built - and similarly, the include and link paths will need to be set in the Makefile.

The makefile is simple and should built both C++ versions, thus if you have both crypto++ and openssl available, you should be able to just "make" and then run the harness ("./runtest-against-erisx.sh").

# Notes
I built and tested this on MacOS, and currently only the python and openssl versions work; no time so far to figure out the complete crypto++ story.

Sample output from the last run is in output.log.