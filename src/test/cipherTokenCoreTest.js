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
        var timestamp = new Date().getTime();
        var accessToken = ctCore.createAccessToken(settings, USER_ID, timestamp, DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(settings, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.equal(accessTokenSet.userId, USER_ID);
        assert.equal(accessTokenSet.timestamp, timestamp);
        assert.deepEqual(accessTokenSet.data, DATA);
    });
});

describe.only('Error description', function () {

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

    it('Should throw an error when trying to create an accessToken without settings', function () {
        try {
            ctCore.createAccessToken({}, USER_ID, new Date().getTime(), DATA);
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