var assert = require('assert');
var ctCore = require('../cipherTokenCore');

const USER_ID = 'John Spartan';
const DATA = 'validData';

var settings = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123'
};

var settingsWithSessionId = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123',
    enableSessionId: true
};

var anotherSettings = {
    cipherKey: 'myCipherKey123',
    firmKey: 'anotherFirmKey'
};

describe('Token generation', function() {

    it('Should generate tokens', function() {
        ctCore.createToken(settings, USER_ID, DATA, function(err, token){
            assert.equal(err, null);
            assert.notEqual(token, null);
        });
    });

    it('Generated token must be decoded back to get original data', function() {
        ctCore.createToken(settings, USER_ID, DATA, function(err, token){
            ctCore.getTokenSet(settings, token, checkTokenSet);
        });
        function checkTokenSet(err, tokenSet){
            assert.notEqual(tokenSet, null);
            assert.equal(tokenSet.userId, USER_ID);
            assert.deepEqual(tokenSet.data, DATA);
        }
    });

    it('Should return an expiresAtTimestamp', function () {
        ctCore.createToken(settings, USER_ID, DATA, function(err, token){
            ctCore.getTokenSet(settings, token, checkTokenSet);
        });
        function checkTokenSet(err, tokenSet){
            assert.notEqual(tokenSet.expiresAtTimestamp, null);
        }
    });

    it('ExpiresInTimestamp should be greater than actual time according to settings', function () {
        var customSettings = {
            cipherKey: 'myCipherKey123',
            firmKey: 'anotherFirmKey',
            tokenExpirationMinutes : 2
        };
        ctCore.createToken(customSettings, USER_ID, DATA, function(err, token) {
            ctCore.getTokenSet(customSettings, token, checkTokenSet);
        });
        function checkTokenSet(err, tokenSet){
            var expected = new Date().getTime() + customSettings.tokenExpirationMinutes*60*1000;
            var expectedRounded = (expected/(60*1000)).toFixed();
            var actualRounded = (tokenSet.expiresAtTimestamp/(60*1000)).toFixed();

            assert.equal(expectedRounded, actualRounded);
        }
    });
});

describe('Error description', function () {

    it('Should return an error when submitted token is invalid', function() {
        var token = 'invalid token';
        ctCore.getTokenSet(settings, token, checkTokenSet);
        function checkTokenSet(err, tokenSet) {
            console.log('err -' + err);
            console.log('tokenSet - ' + tokenSet);
            assert.equal(tokenSet, null);
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Bad token');
        }
    });

    it('Should return an error when trying to decode with invalid firm key', function() {
        ctCore.createToken(settings, USER_ID, DATA, function(err, token){
            ctCore.getTokenSet(anotherSettings, token, checkTokenSet);
        });
        function checkTokenSet(err, tokenSet){
            assert.equal(tokenSet, null);
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Bad firm');
        }
    });

    it('Should return an error when trying to create a token with empty settings', function () {
        ctCore.createToken({}, USER_ID, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        });
    });

    it('Should return an error when trying to create a token with undefined settings', function () {
        ctCore.createToken(undefined, USER_ID, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        });
    });

    it('Should throw an error when cipherKey is missing', function () {
        ctCore.createToken({'firmKey': 'firmKey1234'}, USER_ID, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'CipherKey required');
        });
    });

    it('Should throw an error when firmKey is missing', function () {
        ctCore.createToken({'cipherKey': 'cipherKey1234'}, USER_ID, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'FirmKey required');
        });
    });
});

describe('SessionId support', function() {
    it('Token should have a sessionId when enabled', function() {

        ctCore.createToken(settingsWithSessionId, USER_ID, DATA, function(err, token){
            ctCore.getTokenSet(settingsWithSessionId, token, checkTokenSet);
        });
        function checkTokenSet(err, tokenSet){
            assert.notEqual(tokenSet.sessionId, null);
        }
    });


    it('By default, token creation do not include session ids', function () {
        ctCore.createToken(settings, USER_ID, DATA, function(err, token){
            ctCore.getTokenSet(settings, token, checkTokenSet);
        });
        function checkTokenSet(err, tokenSet){
            assert.equal(tokenSet.sessionId, null);
        }
    });

    it('Session ids should be different for different tokens', function() {
        var firstSessionId = '';
        var secondSessionId = '';

        ctCore.createToken(settingsWithSessionId, 'first user', DATA, function(err, token){
            ctCore.getTokenSet(settingsWithSessionId, token, function(err, tokenSet){
                firstSessionId = tokenSet.sessionId;
            })
        });
        ctCore.createToken(settingsWithSessionId, 'second user', DATA, function (err, token) {
            ctCore.getTokenSet(settingsWithSessionId, token, function (err, tokenSet) {
                secondSessionId = tokenSet.sessionId;
            })
        });

        assert.notEqual(firstSessionId, secondSessionId);
    });

    //TODO: create tokens with a given session id
});

// TODO: test serialization & unserialization
