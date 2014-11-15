var crypto = require('crypto');

var _ERRORS = {
    cipherKeyRequired : {err:'CipherKey required', des:'CipherKey parameter is mandatory'},
    firmKeyRequired : {err:'FirmKey required',des:'FirmKey parameter is mandatory'},
    badFirm : {err:'Bad firm',des:'Firm is not valid'},
    badAccessToken : {err:'Bad accessToken', des:'AccessToken is not valid'},
    accessTokenExpired : {err:'AccessToken expired',des:'AccessToken has expired and it must be renewed'},
    serializationError: {err: 'Serialization error', des: 'Error during data serialization'},
    unserializationError: {err: 'Unserialization error', des: 'Error during data unserialization'}
};

const DEFAULT_SETTINGS = {
    cipherAlgorithm : 'aes-256-cbc',
    hmacAlgorithm : 'md5',
    hmacDigestEncoding : 'hex',
    plainEncoding : 'utf8',
    tokenEncoding : 'base64',
    accessTokenExpirationMinutes : 90,
    enableSessionId: false
};

function enrich_settings(settings){
    for (var p in DEFAULT_SETTINGS) settings[p] = DEFAULT_SETTINGS[p];
    return settings;
}

function serialize(data) {
    try {
        return JSON.stringify(data);
    } catch (e) {
        debug('Serialization error', e);
        throw _ERRORS.serializationError;
    }
}

function unserialize(data) {
    try {
        return JSON.parse(data);
    } catch (e) {
        throw _ERRORS.unserializationError;
    }
}

function standarizeToken(token){
    return token.
        replace(/\+/g, '-'). 	// Convert '+' to '-'
        replace(/\//g, '_'). 	// Convert '/' to '_'
        replace(/=+$/, '') 		// Remove ending '='
        ;
}

function firmAccessToken(settings, userId, timestamp, serializedData) {
    var notFirmedToken = serialize({
        'userId': userId,
        'timestamp': timestamp,
        'data': serializedData
    });
    var firmedToken = crypto.createHmac(settings.hmacAlgorithm, settings.firmKey)
        .update(notFirmedToken)
        .digest(settings.hmacDigestEncoding);
    return firmedToken;
}

function checkAccessTokenFirm(settings, accessToken){
    var accessTokenSet = decipherAccessToken(settings, accessToken);

    var firm = firmAccessToken(settings, accessTokenSet.userId, accessTokenSet.timestamp, accessTokenSet.data);
    return firm === accessTokenSet.firm;
}

function decipherAccessToken (settings, accessToken){
    var decipher = crypto.createDecipher(settings.cipherAlgorithm, settings.cipherKey);
    var decodedToken = decipher.update(accessToken, settings.tokenEncoding, settings.plainEncoding);
    if (!decodedToken) return null;
    decodedToken = (decodedToken + decipher.final(settings.plainEncoding));

    decodedToken = unserialize(decodedToken);
    return decodedToken;
}

exports.createAccessToken = function(settings, userId, timestamp, data) {
    settings = enrich_settings(settings);

    if(!timestamp) timestamp = new Date().getTime();
    data = data || {};

    var firm = firmAccessToken(settings, userId, timestamp, data);

    var cipher = crypto.createCipher(settings.cipherAlgorithm, settings.cipherKey);
    var accessTokenSet = serialize({
        'userId': userId,
        'timestamp': timestamp,
        'data': data,
        'firm': firm
    });
    var encodedData = cipher.update(accessTokenSet, settings.plainEncoding, settings.tokenEncoding);

    return  standarizeToken(encodedData + cipher.final(settings.tokenEncoding));
};

exports.getAccessTokenSet = function(settings, accessToken){
    settings = enrich_settings(settings);
    var tokenSet = {};

    var token = decipherAccessToken(settings, accessToken);
    if (!token){
        tokenSet.err = _ERRORS.badAccessToken;
    } else if(!checkAccessTokenFirm(settings, accessToken)){
        tokenSet.err = _ERRORS.badFirm;
    } else {
        tokenSet = {
            userId : token.userId,
            timestamp : token.timestamp,
            data: token.data
        };
    }
    return tokenSet;
};

