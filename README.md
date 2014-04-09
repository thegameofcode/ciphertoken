ciphertoken
===========

A method to create ciphered accessToken based on the following principles:
* must include id information.
* must include expiration information.
* must be a designed token to transport, but not to store it.

## NodeJS


### Require

```js
var ciphertoken = require('ciphertoken');
```

### Creation

#### Parameters
- __CIPHER_KEY__ : (required) used to cipher the accessToken
- __FIRM_KEY__ : (required) used to firm the accessToken
- __options__ : (options) object with options to set up
- __options.accessTokenExpirationMinutes__ : minutes of accessToken life (90 minutes by default)

```js
var cToken = ciphertoken.create(CIPHER_KEY,FIRM_KEY[,options]);
```

### Methods
- __createRefreshToken()__ : returns a randomBytes encodes to the RFC 4648 Spec
- __createAccessToken(CONSUMMER_ID,TIMESTAMP)__ : returns a ciphered and firmed accessToken
- __getAccessTokenSet(ACCESS_TOKEN[,force])__ : returns an array with the consumerId and timestamp, this method check the firm authenticity and the timestamp expiration (90 minutes by default), force can be used to return the accessToken in any case
- __checkAccessTokenExpiration(ACCESS_TOKEN)__ : returns false when timestamp is expired and true when is valid, also always check the firm authenticity


### Example

```js

var CIPHER_KEY = 'MyCipherKey123';
var FIRM_KEY = 'MyFirmKey123'
var cToken = ciphertoken.create(CIPHER_KEY,FIRM_KEY);

function newUser(callback){
  var refreshToken = cToken.refreshToken();
  var user = { id:1, refTkn:refreshToken };
  db.save(user,callback);
}

function createUserAccess(callback){
  db.get({id:1},function(err,userDb){
    callback(err,{accessToken : cToken.createAccessToken(userDb.id,new Date().getTime()) );
  });
}

function getUserIdByAccessToken(accessToken){
  var accessTokenSet = cToken.getAccessTokenSet(accessToken);
  return accessTokenSet[0]; // userId
}

```







