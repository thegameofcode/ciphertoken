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
        var token = ctCore.createToken(settings, USER_ID, DATA);
        assert.notEqual(token, null);
    });

    it('Generated token must be decoded back to get original data', function() {
        var token = ctCore.createToken(settings, USER_ID, DATA);
        var tokenSet = ctCore.getTokenSet(settings, token);

        assert.notEqual(tokenSet, null);
        assert.equal(tokenSet.userId, USER_ID);
        assert.deepEqual(tokenSet.data, DATA);
    });

    it('Should return an expiresAtTimestamp', function () {
        var token = ctCore.createToken(settings, USER_ID, DATA);
        var tokenSet = ctCore.getTokenSet(settings, token);

        assert.notEqual(tokenSet.expiresAtTimestamp, null);
    });

    it('ExpiresInTimestamp should be greater than actual time according to settings', function () {
        var customSettings = {
            cipherKey: 'myCipherKey123',
            firmKey: 'anotherFirmKey',
            tokenExpirationMinutes : 2
        };
        var token = ctCore.createToken(customSettings, USER_ID, DATA);
        var tokenSet = ctCore.getTokenSet(customSettings, token);
        var expected = new Date().getTime() + customSettings.tokenExpirationMinutes*60*1000;
        var expectedRounded = (expected/(60*1000)).toFixed();
        var actualRounded = (tokenSet.expiresAtTimestamp/(60*1000)).toFixed();

        assert.equal(expectedRounded, actualRounded);
    });
});

describe('Error description', function () {

    it('Should return an error when submitted token is invalid', function() {
        var token = 'invalid token';
        var tokenSet = ctCore.getTokenSet(settings, token);

        assert.notEqual(tokenSet, null);
        assert.notEqual(tokenSet.err, null);
        assert.strictEqual(tokenSet.err.err, 'Bad token');
    });

    it('Should return an error when trying to decode with invalid firm key', function() {
        var token = ctCore.createToken(settings, USER_ID, DATA);
        var tokenSet = ctCore.getTokenSet(anotherSettings, token);

        assert.notEqual(tokenSet, null);
        assert.notEqual(tokenSet.err, null);
        assert.strictEqual(tokenSet.err.err, 'Bad firm');
    });

    it('Should throw an error when trying to create a token with empty settings', function () {
        try {
            ctCore.createToken({}, USER_ID, DATA);
        } catch(err) {
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        }
    });

    it('Should throw an error when trying to create a token with undefined settings', function () {
        try {
            ctCore.createToken(undefined, USER_ID, DATA);
        } catch(err) {
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        }
    });

    it('Should throw an error when cipherKey is missing', function () {
        try {
           ctCore.createToken({'firmKey': 'firmKey1234'}, USER_ID, DATA);
        } catch(err) {
           assert.notEqual(err, null);
           assert.strictEqual(err.err, 'CipherKey required');
        }
    });

    it('Should throw an error when firmKey is missing', function () {
        try {
            ctCore.createToken({'cipherKey': 'cipherKey1234'}, USER_ID, DATA);
        } catch(err) {
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'FirmKey required');
        }
    });
});

describe('SessionId support', function() {
    it('Token should have a sessionId when enabled', function() {
        var token = ctCore.createToken(settingsWithSessionId, USER_ID, DATA);
        var tokenSet = ctCore.getTokenSet(settingsWithSessionId, token);

        assert.notEqual(tokenSet.sessionId, null);
    });

    it('By default, token creation do not include session ids', function () {
        var token = ctCore.createToken(settings, USER_ID, DATA);
        var tokenSet = ctCore.getTokenSet(settings, token);

        assert.equal(tokenSet.sessionId, null);
    });

    it('Session ids should be different for different tokens', function() {
        var firstToken = ctCore.createToken(settingsWithSessionId, 'first user', DATA);
        var firstTokenSet = ctCore.getTokenSet(settingsWithSessionId, firstToken);
        var secondToken = ctCore.createToken(settingsWithSessionId, 'second user', DATA);
        var secondTokenSet = ctCore.getTokenSet(settingsWithSessionId, secondToken);

        assert.notEqual(firstTokenSet.sessionId, secondTokenSet.sessionId);
    });
});
