echo "Executing Funding API test against clearing.newrelease.erisx.com"

echo "\n\nPython version - verifies the test harness"
node drive-funding-api.js "python3 signing-example.py" "<API Key>" "<API Secret>" "<Funding password>" 

echo "\n\nC++ openssl version"
node drive-funding-api.js "./signing-example-cpp-openssl" "<API Key>" "<API Secret>" "<Funding password>" 

echo "\n\nC++ cryptopp version"
node drive-funding-api.js "./signing-example-cpp-cryptopp" "<API Key>" "<API Secret>" "<Funding password>" 

