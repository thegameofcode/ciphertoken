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
    cipherKeyRequired : {err:'CipherKey required', des:'CipherKey parameter is mandatory'},
    firmKeyRequired : {err:'FirmKey required',des:'FirmKey parameter is mandatory'},
    badFirm : {err:'Bad firm',des:'Firm is not valid'},
    badAccessToken : {err:'Bad accessToken', des:'AccessToken is not valid'},
    accessTokenExpired : {err:'AccessToken expired',des:'AccessToken has expired and it must be renewed'},
    serializationError: {err: 'Serialization error', des: 'Error during data serialization'},
    unserializationError: {err: 'Unserialization error', des: 'Error during data unserialization'}
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

function decipherAccessToken (settings, accessToken){
    var decipher = crypto.createDecipher(settings.cipherAlgorithm, settings.cipherKey);
    var decodedToken = decipher.update(accessToken, settings.tokenEncoding, settings.plainEncoding);
    if (!decodedToken) return null;
    decodedToken =  (decodedToken + decipher.final(settings.plainEncoding)).split(SEPARATOR);
    decodedToken[2] = unserialize(decodedToken[2]);
    return decodedToken;
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

    var token = decipherAccessToken(settings, accessToken);
    if (!token){
        tokenSet.err = _ERRORS.badAccessToken;
    } else {
        tokenSet = { userId : token[0], timestamp : token[1], data: token[2]};
    }
    return tokenSet;
};

