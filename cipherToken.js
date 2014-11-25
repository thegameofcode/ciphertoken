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

function serialize(data, cbk) {
    var res;
    try {
        res = JSON.stringify(data);
    } catch (e) {
        return cbk(ERRORS.serializationError);
    }
    cbk(null, res);
}

function unserialize(data, cbk) {
    var res;
    try {
        res = JSON.parse(data);
    } catch (e) {
        return cbk(ERRORS.unserializationError);
    }
    cbk(null,res);
}

function standarizeToken(token){
    return token.
        replace(/\+/g, '-'). 	// Convert '+' to '-'
        replace(/\//g, '_'). 	// Convert '/' to '_'
        replace(/=+$/, '')      // Remove ending '='
        ;
}

function firmToken(settings, userId, expiresAtTimestamp, data, cbk) {
    var dataToSerialize = {
        'userId': userId,
        'expiresAtTimestamp': expiresAtTimestamp,
        'data': data
    };

    serialize(dataToSerialize, function(err, notFirmedToken){
        if(err){
            return cbk(err, null);
        }
        var firmedToken = crypto.createHmac(settings.hmacAlgorithm, settings.firmKey)
            .update(notFirmedToken)
            .digest(settings.hmacDigestEncoding);
        cbk(null, firmedToken);
    });
}

function checkTokenFirm(settings, cipheredToken, cbk){
    decipherToken(settings, cipheredToken, function(err, tokenSet){
        firmToken(settings, tokenSet.userId, tokenSet.expiresAtTimestamp, tokenSet.data, function(err, firm){
            if(err){
                return cbk(err, null);
            }
            cbk(null, firm === tokenSet.firm);
        });
    });
}

function decipherToken(settings, cipheredToken, cbk){
    var decipher = crypto.createDecipher(settings.cipherAlgorithm, settings.cipherKey);
    var decodedToken = decipher.update(cipheredToken, settings.tokenEncoding, settings.plainEncoding);
    if (!decodedToken){
        return cbk(ERRORS.badToken, null);
    }
    decodedToken = (decodedToken + decipher.final(settings.plainEncoding));

    unserialize(decodedToken, function(err, decodedToken){
        if(err){
            return cbk(err, null);
        }
        cbk(null, decodedToken);
    });
}

function createToken(settings, userId, sessionId, data, cbk) {
    enrichSettings(settings, function(err, settings){
        if(err){
            return cbk(err, null);
        }
        var expiresAtTimestamp = new Date().getTime() + settings.tokenExpirationMinutes*60*1000;
        data = data || {};

        firmToken(settings, userId, expiresAtTimestamp, data, function(err, firm){
            if(err){
                return cbk(err, null);
            }
            var cipher = crypto.createCipher(settings.cipherAlgorithm, settings.cipherKey);

            var tokenSet = {
                userId: userId,
                expiresAtTimestamp: expiresAtTimestamp,
                data: data,
                firm: firm
            };
            if (settings.enableSessionId) {
                if (sessionId == null) {
                    tokenSet.sessionId = userId + '-' + crypto.pseudoRandomBytes(12).toString('hex');
                } else {
                    tokenSet.sessionId = sessionId;
                }
            }

            serialize(tokenSet, function(err, notFirmedToken){
                if(err){
                    return cbk(err, null);
                }
                var encodedData = cipher.update(notFirmedToken, settings.plainEncoding, settings.tokenEncoding);

                cbk(null, standarizeToken(encodedData + cipher.final(settings.tokenEncoding)));
            });
        });
    });
}

function getTokenSet(settings, cipheredToken, cbk){
    enrichSettings(settings, function(err, settings){
        if (err) {
            return cbk(err, null);
        }

        decipherToken(settings, cipheredToken, function(err, token){
            if(err){
                return cbk(err, null);
            }

            checkTokenFirm(settings, cipheredToken, function(err, isValid){
                if(err){
                    return cbk(err, null);
                }

                if(!isValid) {
                    return cbk(ERRORS.badFirm, null);
                }

                var tokenSet = {
                    userId: token.userId,
                    expiresAtTimestamp: token.expiresAtTimestamp,
                    data: token.data
                };

                if (settings.enableSessionId) {
                    tokenSet.sessionId = token.sessionId
                }

                cbk(null, tokenSet);
            });
        });
    });
}

module.exports = {
    createToken: createToken,
    getTokenSet: getTokenSet
};

// TODO: Use jwt instead of crypto for token encoding
