var crypto = require('crypto');

const SEPARATOR = '_`$ep@r4t0r`_';
const DEFAULT_SETTINGS = {
    cipherAlgorithm : 'aes-256-cbc',
    hmacAlgorithm : 'md5',
    hmacDigestEncoding : 'hex',
    plainEncoding : 'utf8',
    tokenEncoding : 'base64',
    accessTokenExpirationMinutes : 90,
    enableSessionId: false
};

var _ERRORS = {
    cipherKeyRequired : {err:'cipherKey required', des:'cipherKey parameter is mandatory'},
    firmKeyRequired : {err:'firmKey required',des:'firmKey parameter is mandatory'},
    badFirm : {err:'bad firm',des:'firm is not valid'},
    badAccessToken : {err:'bad accessToken', des:'accessToken is not valid'},
    accessTokenExpired : {err:'accessToken expired',des:'accessToken has expired and it must be renewed'},
    serializationError: {err: 'serialization error', des: 'error during data serialization'},
    unserializationError: {err: 'unserialization error', des: 'error during data unserialization'}
};

function serialize(data) {
    try {
        return JSON.stringify(data);
    } catch (e) {
        debug('Serialization error', e);
        throw _ERRORS.serializationError;
    }
}

function standarizeToken(token){
    return token.
        replace(/\+/g, '-'). 	// Convert '+' to '-'
        replace(/\//g, '_'). 	// Convert '/' to '_'
        replace(/=+$/, '') 		// Remove ending '='
        ;
}

function unserialize(data) {
    try {
        return JSON.parse(data);
    } catch (e) {
        throw _ERRORS.unserialization_error;
    }
}

function firmAccessToken(settings, userId, timestamp, serializedData) {
    var firmedToken = crypto.createHmac(settings.hmacAlgorithm, settings.firmKey)
        .update(userId + timestamp + serializedData)
        .digest(settings.hmacDigestEncoding);
    return firmedToken;
}
exports.createAccessToken = function(settings, userId, timestamp, data) {
    for (var p in DEFAULT_SETTINGS) settings[p] = DEFAULT_SETTINGS[p];

    if(!timestamp) timestamp = new Date().getTime();
    data = data || {};
    var serializedData = serialize(data);

    var firmedToken = firmAccessToken(settings, userId, timestamp, serializedData);

    var cipher = crypto.createCipher(settings.cipherAlgorithm, settings.cipherKey);
    var accessTokenSet = [userId, timestamp, serializedData, firmedToken];
    var encodedData = cipher.update(accessTokenSet.join(SEPARATOR), settings.plainEncoding, settings.tokenEncoding);

    return  standarizeToken(encodedData + cipher.final(settings.tokenEncoding));
};

exports.getAccessTokenSet = function(settings, accessToken){
    var tokenSet = {};

    var decipher = crypto.createDecipher(settings.cipherAlgorithm, settings.cipherKey);


    var token = decipher.update(accessToken, settings.tokenEncoding, settings.plainEncoding);
    token =  (token + decipher.final(settings.plainEncoding)).split(SEPARATOR);
    token[2] = unserialize(token[2]);

    console.log(token);

    tokenSet = { userId : token[0], timestamp : token[1], data: token[2]};

    return tokenSet;
};
