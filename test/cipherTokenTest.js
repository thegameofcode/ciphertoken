var assert = require('assert');
var cipherToken = require('../cipherToken');

const USER_ID = 'John Spartan';
const DATA = {field1:'a1b2c3d4e5f6'};

var settings = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123'
};

var settingsWithSessionId = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123',
    enableSessionId: true
};

var settingsWithDifferentFirmKey = {
    cipherKey: 'myCipherKey123',
    firmKey: 'anotherFirmKey'
};

var settingsWithDifferentCipherKey = {
    cipherKey: 'anotherCipherKey123',
    firmKey:  'myFirmKey123'
};

describe('Token generation', function() {
    it('Should generate tokens', function() {
        cipherToken.encode(settings, USER_ID, null, DATA, function(err, token){
            assert.equal(err, null);
            assert.notEqual(token, null);
        });
    });

    it('Generated token must be decoded back to get original data', function() {
        cipherToken.encode(settings, USER_ID, null, DATA, function(err, token){
            cipherToken.decode(settings, token, function(err, tokenSet){
                assert.equal(err, null);
                assert.notEqual(tokenSet, null);
                assert.equal(tokenSet.userId, USER_ID);
                assert.deepEqual(tokenSet.data, DATA);
            });
        });
    });

    it('Should return an expiresAtTimestamp', function () {
        cipherToken.encode(settings, USER_ID, null, DATA, function(err, token){
            cipherToken.decode(settings, token, function(err, tokenSet){
                assert.notEqual(tokenSet.expiresAtTimestamp, null);
            });
        });
    });

    it('ExpiresInTimestamp should be greater than actual time according to settings', function () {
        var customSettings = {
            cipherKey: 'myCipherKey123',
            firmKey: 'anotherFirmKey',
            tokenExpirationMinutes : 2
        };
        cipherToken.encode(customSettings, USER_ID, null, DATA, function(err, token) {
            cipherToken.decode(customSettings, token, function(err, tokenSet){
                assert.equal(err, null);
                var expected = new Date().getTime() + customSettings.tokenExpirationMinutes*60*1000;
                var expectedRounded = (expected/(60*1000)).toFixed();
                var actualRounded = (tokenSet.expiresAtTimestamp/(60*1000)).toFixed();

                assert.equal(expectedRounded, actualRounded);
            });
        });

    });
});

describe('Error description', function () {
    it('Should return an error when submitted token is invalid', function() {
        var token = 'invalid token';
        cipherToken.decode(settings, token, function(err, tokenSet) {
            assert.equal(tokenSet, null);
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Bad token');
        });
    });

    it('Should return an error when trying to decode with invalid firm key', function() {
        cipherToken.encode(settings, USER_ID, null, DATA, function(err, token){
            cipherToken.decode(settingsWithDifferentFirmKey, token, function(err, tokenSet){
                assert.equal(tokenSet, null);
                assert.notEqual(err, null);
                assert.strictEqual(err.err, 'Bad credentials');
            });
        });
    });

    it('Should return an error when trying to create a token with empty settings', function () {
        cipherToken.encode({}, USER_ID, null, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        });
    });

    it('Should return an error when trying to create a token with undefined settings', function () {
        cipherToken.encode(undefined, USER_ID, null, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        });
    });

    it('Should return an error when cipherKey is missing', function () {
        cipherToken.encode({'firmKey': 'firmKey1234'}, USER_ID, null, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'CipherKey required');
        });
    });

    it('Should return an error when firmKey is missing', function () {
        cipherToken.encode({'cipherKey': 'cipherKey1234'}, USER_ID, null, DATA, function(err){
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'FirmKey required');
        });
    });

    it('Should return an error when trying to decode with incorrect settings', function(){
        cipherToken.encode(settings, USER_ID, null, DATA, function(err, token){
            cipherToken.decode(settingsWithDifferentCipherKey, token, function(err, tokenSet){
                assert.equal(tokenSet, null);
                assert.notEqual(err, null);
                assert.strictEqual(err.err, 'Bad credentials');
            });
        });
    });
});

describe('SessionId support', function() {
    it('Token should have a sessionId when enabled', function() {

        cipherToken.encode(settingsWithSessionId, USER_ID, null, DATA, function(err, token){
            cipherToken.decode(settingsWithSessionId, token, function(err, tokenSet){
                assert.notEqual(tokenSet.sessionId, null);
            });
        });
    });

    it('By default, token creation do not include session ids', function () {
        cipherToken.encode(settings, USER_ID, null, DATA, function(err, token){
            cipherToken.decode(settings, token, function(err, tokenSet){
                assert.equal(tokenSet.sessionId, null);
            });
        });
    });

    it('Session ids should be different for different tokens', function() {
        var firstSessionId = '';
        var secondSessionId = '';

        cipherToken.encode(settingsWithSessionId, 'first user', null, DATA, function(err, token){
            cipherToken.decode(settingsWithSessionId, token, function(err, tokenSet){
                firstSessionId = tokenSet.sessionId;
            })
        });
        cipherToken.encode(settingsWithSessionId, 'second user', null, DATA, function (err, token) {
            cipherToken.decode(settingsWithSessionId, token, function (err, tokenSet) {
                secondSessionId = tokenSet.sessionId;
            })
        });

        assert.notEqual(firstSessionId, secondSessionId);
    });

    it('New token can be created with a given sessionId', function(){
        var sessionId = 'abc123456';
        cipherToken.encode(settingsWithSessionId, USER_ID, sessionId, DATA, function(err, token){
            cipherToken.decode(settingsWithSessionId, token, function(err, tokenSet){
                assert.equal(err, null);
                assert.equal(tokenSet.sessionId, sessionId)
            });
        });
    });
});
