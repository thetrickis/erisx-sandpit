// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// Test harness to verify funding-request signature in external application (e.g. c++)
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

const jwt = require('jsonwebtoken');
const axios = require('axios').default;
var execSync = require('child_process').execSync;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function requestAccounts(aToken) { 
  process.stdout.write("Accounts request issued, received: ")
  return new Promise( function(resolve, reject) { axios({ method: 'POST',
            url: `https://clearing.newrelease.erisx.com/api/v1/accounts`, timeout: 30000, // 30 seconds
            headers: { Authorization: `Bearer ${aToken}`, },
            data: {} })
            .then(function (response) {
                resolve(response.data)
            })
            .catch(function (error) {
                reject(error)

            });
          });  
} // requestAccounts

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function requestLinkedAccounts(aToken) { 
  process.stdout.write("Linked accounts request issued, received: ")
  return new Promise( function(resolve, reject) { axios({ method: 'POST',
        url: `https://clearing.newrelease.erisx.com/api/v1/linked_accounts`, timeout: 30000, // 30 seconds
        headers: { Authorization: `Bearer ${aToken}`, },
        data: {} })
        .then(function (response) {
            resolve(response.data)
          })
          .catch(function (error) {
            reject(error)
          });
        });
} // requestLinkedAccounts

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function requestBuildWithdrawal(aToken, aFrom, aTo) { 
  process.stdout.write("Build withdrawal request issued, received: ")
  return new Promise( function(resolve, reject) { axios({ method: 'POST',
        url: `https://clearing.newrelease.erisx.com/api/v1/build_withdrawal_request`, timeout: 30000, // 30 seconds
        headers: { Authorization: `Bearer ${aToken}`, },
        data: { 'account_id': `${aFrom}`, 
                'linked_account_id': `${aTo}`, 
                'funds_designation': `N`, 
                'amount': `0.01`
        } })
        .then(function (response) {
            resolve(response.data)
        })
        .catch(function (error) {
          reject(error)
        });
      });
} // requestBuildWithdrawal

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function submitWithdrawalRequest( aToken, aRequestData, aSignature ) {
  process.stdout.write("Submit withdrawal request issued, received: ")
  return new Promise( function(resolve, reject) { axios({ method:'POST',
          url: 'https://clearing.newrelease.erisx.com/api/v1/submit_withdrawal_request', timeout: 30000,
          headers: { Authorization: `Bearer ${aToken}`, },
          data: { 'request_data': aRequestData,
                  'signature': `${aSignature}`
        } })        
      .then(function (response) {
        resolve(response.data)
      })
      .catch(function (error) {
        reject(error)
      });
    });
} // submitWithdrawalRequest


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
async function RunTest( aApiKey, aSecret, aFundingPass, aExternalSigningApp )
{
  console.log("Begin test to verify funding-request signature in external application")
  var lContinue = true

  // Sign token
  var lPayload = {
    iat: Date.now(),
    sub: aApiKey
  };
  var lToken = jwt.sign( lPayload, aSecret, { algorithm: 'HS256'});

  // Fetch account list
  var accountsResult = await requestAccounts(lToken).catch((err) => { console.error(err); lContinue = false; });
  if (!lContinue) { console.log("Exiting on error: test failed."); return;};

  // Grab the first account to use as from-account in the withdrawal test
  if ( accountsResult.count < 1 ) { console.log("No clearing accounts defined"); return; }
  var lFromAccount = accountsResult.accounts[0].account_id
  console.log("OK. Will withdraw from: " + lFromAccount)
  
  // Fetch linked-account list
  var linkedAccountsResult = await requestLinkedAccounts(lToken).catch((err) => { console.error(err); lContinue = false; });
  if (!lContinue) { console.log("Exiting on error: test failed."); return; };
  var lToAccount = linkedAccountsResult.account_id

  // Grab the first account to use as to-account in the withdrawal test
  if ( linkedAccountsResult.count < 1 ) { console.log("No linked accounts defined"); return; }
  var lToAccount = linkedAccountsResult.accounts[0].id
  console.log("OK. Will place in: " + lToAccount)
  
  // Prepare withdrawal - get request data
  var lBuildWithdrawalResult = await requestBuildWithdrawal(lToken, lFromAccount, lToAccount).catch((err) => { console.error(err); lContinue = false; });
  if (!lContinue) { console.log("Exiting on error: test failed."); return;};
  var lAuthId = lBuildWithdrawalResult.auth_id
  var lWithdrawalRequestdata = lBuildWithdrawalResult.request_data
  var lEscapedWithdrawalRequestdata = ""

  // Set the lWithdrawalRequestsData... escaping any quotes, as we'll be passing on the comamnd line.
  for (var i = 0; i < lWithdrawalRequestdata.length; i++) {
    var lChar = lWithdrawalRequestdata.charAt(i);
    if ( lChar == '"' ) lEscapedWithdrawalRequestdata += "\\";
    lEscapedWithdrawalRequestdata += lChar;
  }

  if ( lAuthId && lEscapedWithdrawalRequestdata )
  {
    console.log("OK. AuthId and RequestData retreived." )
  }
  else
  {
    console.log("No valid details from build-withdrawal.")
    return
  }
  
  // Call out to external application to test different language based signing (e.g. c++)
  var lRequestDataSignature = ""
  process.stdout.write(`Invoking external application to sign request data (${aExternalSigningApp}): `);

  try
  {
    var lExecString = lSigningApp + ` "${lEscapedWithdrawalRequestdata}" "${lAuthId}" "${aFundingPass}"`
    var lRequestDataSignature = execSync( lExecString );
    if (lRequestDataSignature)
    {
      lRequestDataSignature = lRequestDataSignature.toString().trim();
      console.log("Received signature: " + lRequestDataSignature)
    }
    else
    {
      console.log("No valid signature received, test failed.")
      return
    }
  }
  catch ( error )
  {
    console.log("An error occurred executing " + lExecString )
    console.log(error)
    return
  }

  // Issue actual withdrawal request
  var lWithdrawalResult = await submitWithdrawalRequest( lToken, lWithdrawalRequestdata, lRequestDataSignature ).catch((err) => { console.log("received error response from server..."); console.error(err.response.data); lContinue = false; });
  if ( lContinue )
    console.log("OK. Withdrawal request completed successfully.");
  else
    console.log("Withdrawal request failed.");
} // RunTest

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
var lApiKey = "TO-PASSED-IN";
var lSecret = "TO-PASSED-IN";
var lFundingPass = "TO-PASSED-IN";
var lSigningApp = "TO-PASSED-IN";

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// Retreive the args (expecting api-key, api-secret, funding-password and signing-app-path)
process.argv.forEach(function (val, index, array) {
  switch ( index )
  {
    case 2:
      lSigningApp = val;
      break;
    case 3:
      lApiKey = val;
      break;
    case 4:
      lSecret = val;
      break;
    case 5:
      lFundingPass = val;
      break;
  }
});

// Run
RunTest( lApiKey, lSecret, lFundingPass, lSigningApp )