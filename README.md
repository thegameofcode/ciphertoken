--WORK IN PROGRESS--

cipherToken
===========

A method to create ciphered accessToken based on the following principles:
* must include id information.
* must include expiration information.
* must be a designed token to transport, but not to store it.

## NodeJS


### Require

```js
var cipherToken = require('cipherToken');
```

### Usage

cipherToken is designed to be used as a module.

Tokens are created this way

```js
cipherToken.createToken(settings, user_id, session_id, data, function(err, token){});
```


and can be decoded back to a more readable state with


```js
cipherToken.getTokenSet(settings, token, function(err, tokenSet){});
```


#### Settings

Settings is a hash with the following properties

- __cipherKey__ : (required) used to cipher the accessToken
- __firmKey__ : (required) used to firm the accessToken
- __tokenExpirationMinutes__ : minutes of accessToken life (__90__ minutes by default)
- __cipherAlgorithm__ : algorithm used to cipher the token (__aes-256-cbc__ by default)
- __hmacAlgorithm__ : algorithm used to build the hmac (__md5__ by default)
- __hmacDigestEncoding__ : encoding used in the outbound of the hmac digest (__hex__ by default)
- __plainEncoding__ : encoding used in the data content in the token (__utf8__ by default)
- __tokenEncoding__ : encoding used in the token format (__base64__ by default)
- __enableSessionId__ : sessionId of an accessToken, can be preset at accessToken creation

Settings must be passed to cipherToken in each call. Only cipherKey and firmKey are required.


### Method: createToken

```js
cipherToken.createToken(settings, user_id, session_id, data, function(err, token){});
```

To create a token the first thing you need to do is to define your settings.
UserId can be an username or any other thing you use to identify your clients.
SessionId is only when you want to create a token associated to the same session of another token (usually near expiration).
SessionId can be null.
Data is to encode the payload you want to travel with the token.

cipherToken.createToken expects a callback in the error-result form.



### Method: getTokenSet

```js
cipherToken.getTokenSet(settings, token, function(err, tokenSet){});
```

Same settings of creation must be provided in order to decode the token.

tokenSet has the following properties

- userId: the same as the provided one
- expiresAtTimestamp: at creation, gets the actual time and add to it the time expiration to calculate when will the token expire.
Cipher token doesn't care if the token has expired or not.
- data: same as provided
- sessionId: (if enabled) random the first time, after that previous one can be used

### Example

```js 
var userId = 'John Spartan';
var data = 'validData';

var settings = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123'
};

var cipherToken = require('cipherToken');

cipherToken.createToken(settings, userId, null, data, doWhateverYouWantWithYourToken);
function doWhateverYouWantWithYourToken(err, token){

}

cipherToken.getTokenSet(settings, validToken, function(err, tokenSet){
    console.log(tokenSet.userId);
    console.log(tokenSet.data);
    console.log(tokenSet.expiresAtTimestamp);
});

```







