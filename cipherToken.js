var crypto = require('crypto');

var ERRORS = {
    settingsRequired: {
        err: 'Settings required',
        des: 'Settings must have at least cipherKey and firmKey'
    },
    cipherKeyRequired: {
        err: 'CipherKey required',
        des: 'CipherKey parameter is mandatory'
    },
    firmKeyRequired: {
        err: 'FirmKey required',
        des: 'FirmKey parameter is mandatory'
    },
    badFirm: {
        err: 'Bad firm',
        des: 'Firm is not valid'
    },
    badToken: {
        err: 'Bad token',
        des: 'Token is not valid'
    },
    serializationError: {
        err: 'Serialization error',
        des: 'Error during data serialization'
    },
    unserializationError: {
        err: 'Unserialization error',
        des: 'Error during data unserialization'
    }
};

const DEFAULT_SETTINGS = {
      cipherAlgorithm:          'aes-256-cbc',
      hmacAlgorithm:            'md5',
      hmacDigestEncoding:       'hex',
      plainEncoding:            'utf8',
      tokenEncoding:            'base64',
      tokenExpirationMinutes:   90,
      enableSessionId:          false
};

function enrichSettings(settings, ckb){
    if (typeof settings === 'undefined' || isEmpty(settings)){
        return ckb(ERRORS.settingsRequired);
    } else if (!settings.hasOwnProperty('cipherKey')) {
        return ckb(ERRORS.cipherKeyRequired);
    } else if (!settings.hasOwnProperty('firmKey')) {
        return ckb(ERRORS.firmKeyRequired);
    }
    for (var p in DEFAULT_SETTINGS){
        if (settings.hasOwnProperty(p) == false) {
            settings[p] = DEFAULT_SETTINGS[p];
        }
    }
    ckb(null, settings);
}

function isEmpty(obj) {
    return !Object.keys(obj).length > 0;
}

function serialize(data) {
    try {
        return JSON.stringify(data);
    } catch (e) {
        throw ERRORS.serializationError;
    }
}

function unserialize(data) {
    try {
        return JSON.parse(data);
    } catch (e) {
        throw ERRORS.unserializationError;
    }
}

function standarizeToken(token){
    return token.
        replace(/\+/g, '-'). 	// Convert '+' to '-'
        replace(/\//g, '_'). 	// Convert '/' to '_'
        replace(/=+$/, '')      // Remove ending '='
    ;
}

function firmToken(settings, userId, expiresAtTimestamp, data) {
    var notFirmedToken = serialize({
        'userId': userId,
        'expiresAtTimestamp': expiresAtTimestamp,
        'data': data
    });
    var firmedToken = crypto.createHmac(settings.hmacAlgorithm, settings.firmKey)
        .update(notFirmedToken)
        .digest(settings.hmacDigestEncoding);
    return firmedToken;
}

function checkTokenFirm(settings, cipheredToken){
    var tokenSet = decipherToken(settings, cipheredToken);

    var firm = firmToken(settings, tokenSet.userId, tokenSet.expiresAtTimestamp, tokenSet.data);
    return firm === tokenSet.firm;
}

function decipherToken (settings, cipheredToken){
    var decipher = crypto.createDecipher(settings.cipherAlgorithm, settings.cipherKey);
    var decodedToken = decipher.update(cipheredToken, settings.tokenEncoding, settings.plainEncoding);
    if (!decodedToken) return null;
    decodedToken = (decodedToken + decipher.final(settings.plainEncoding));

    decodedToken = unserialize(decodedToken);
    return decodedToken;
}

function createToken(settings, userId, sessionId, data, callback) {
    enrichSettings(settings, function(err, settings){
        if(err){
            return callback(err);
        }
        var expiresAtTimestamp = new Date().getTime() + settings.tokenExpirationMinutes*60*1000;
        data = data || {};

        var firm = firmToken(settings, userId, expiresAtTimestamp, data);
        var cipher = crypto.createCipher(settings.cipherAlgorithm, settings.cipherKey);

        var tokenSet = {
            'userId':               userId,
            'expiresAtTimestamp':   expiresAtTimestamp,
            'data':                 data,
            'firm':                 firm
        };
        if (settings.enableSessionId) {
            if (sessionId == null) {
                tokenSet.sessionId = userId + '-' + crypto.pseudoRandomBytes(12).toString('hex');
            } else {
                tokenSet.sessionId = sessionId;
            }
        }
        var encodedData = cipher.update(serialize(tokenSet), settings.plainEncoding, settings.tokenEncoding);

        return callback(null, standarizeToken(encodedData + cipher.final(settings.tokenEncoding)));
    });
}

function getTokenSet(settings, cipheredToken, callback){
    enrichSettings(settings, function(err, settings){
        if (err) {
            return callback(err);
        }
        var tokenSet = {};

        var token = decipherToken(settings, cipheredToken);
        if (!token){
            return callback(ERRORS.badToken);
        } else if(!checkTokenFirm(settings, cipheredToken)){
            return callback(ERRORS.badFirm);
        } else {
            tokenSet = {
                userId : token.userId,
                expiresAtTimestamp : token.expiresAtTimestamp,
                data: token.data
            };
            if (settings.enableSessionId) {
                tokenSet.sessionId = token.sessionId
            }
        }
        return callback(null, tokenSet);
    });
}

module.exports = {
    createToken: createToken,
    getTokenSet: getTokenSet
};

// TODO: Use jwt instead of crypto for token encoding