var assert = require('assert');
var ctCore = require('../cipherTokenCore');

const USER_ID = 'userId';
const DATA = 'validData';

var settings = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123'
};

var anotherSettings = {
    cipherKey: 'myCipherKey123',
    firmKey: 'anotherFirmKey'
};

describe('Access token generation', function(){

    it('Should generate access token', function(){
        var accessToken = ctCore.createAccessToken(settings, USER_ID, new Date().getTime(), DATA);
        assert.notEqual(accessToken, null);
    });

    it('Generated access token must be decoded back to get original data', function(){
        var accessToken = ctCore.createAccessToken(settings, USER_ID, DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(settings, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.equal(accessTokenSet.userId, USER_ID);
        assert.deepEqual(accessTokenSet.data, DATA);
    });

    it('Should return an expiresAtTimestamp', function () {
        var accessToken = ctCore.createAccessToken(settings, USER_ID, DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(settings, accessToken);

        assert.notEqual(accessTokenSet.expiresAtTimestamp, null);
    });

    it('ExpiresInTimestamp should be greater than actual time according to settings', function () {
        var customSettings = {
            cipherKey: 'myCipherKey123',
            firmKey: 'anotherFirmKey',
            accessTokenExpirationMinutes : 2
        };
        var accessToken = ctCore.createAccessToken(customSettings, USER_ID, DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(customSettings, accessToken);
        var expected = new Date().getTime() + customSettings.accessTokenExpirationMinutes*60*1000;
        var expectedRounded = (expected/(60*1000)).toFixed();
        var actualRounded = (accessTokenSet.expiresAtTimestamp/(60*1000)).toFixed();

        assert.equal(expectedRounded, actualRounded);
    });

    it('Should return an expiresIn property', function () {
        var customSettings = {
            cipherKey: 'myCipherKey123',
            firmKey: 'anotherFirmKey',
            accessTokenExpirationMinutes : 5
        };
        var accessToken = ctCore.createAccessToken(customSettings, USER_ID, DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(customSettings, accessToken);

        assert.notEqual(accessTokenSet.expiresIn, null);
        assert.equal(accessTokenSet.expiresIn, customSettings.accessTokenExpirationMinutes);
    });
});

describe('Error description', function () {

    it('Should return an error when submitted access token is invalid', function() {
        var accessToken = 'invalid access token';
        var accessTokenSet = ctCore.getAccessTokenSet(settings, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.notEqual(accessTokenSet.err, null);
        assert.strictEqual(accessTokenSet.err.err, 'Bad accessToken');
    });

    it('Should return an error when trying to decode with invalid firm key', function(){
        var accessToken = ctCore.createAccessToken(settings, USER_ID, new Date().getTime(), DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(anotherSettings, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.notEqual(accessTokenSet.err, null);
        assert.strictEqual(accessTokenSet.err.err, 'Bad firm');
    });

    it('Should throw an error when trying to create an accessToken with empty settings', function () {
        try {
            ctCore.createAccessToken({}, USER_ID, new Date().getTime(), DATA);
        } catch(err) {
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        }
    });

    it('Should throw an error when trying to create an accessToken with undefined settings', function () {
        try {
            ctCore.createAccessToken(undefined, USER_ID, new Date().getTime(), DATA);
        } catch(err) {
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'Settings required');
        }
    });

    it('Should throw an error when cipherKey is missing', function () {
        try {
           ctCore.createAccessToken({'firmKey': 'firmKey1234'}, USER_ID, new Date().getTime(), DATA);
        } catch(err) {
           assert.notEqual(err, null);
           assert.strictEqual(err.err, 'CipherKey required');
        }
    });

    it('Should throw an error when firmKey is missing', function () {
        try {
            ctCore.createAccessToken({'cipherKey': 'cipherKey1234'}, USER_ID, new Date().getTime(), DATA);
        } catch(err) {
            assert.notEqual(err, null);
            assert.strictEqual(err.err, 'FirmKey required');
        }
    })
});
