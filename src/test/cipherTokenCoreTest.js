var assert = require('assert');
var ctCore = require('../cipherTokenCore');

const USER_ID = 'userId';
const DATA = 'validData';

var config = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123'
};

var anotherConfig = {
    cipherKey: 'myCipherKey123',
    firmKey: 'anotherFirmKey'
};

describe('Access token generation', function(){

    it('Should generate access token', function(){
        var accessToken = ctCore.createAccessToken(config, USER_ID, new Date().getTime(), DATA);
        assert.notEqual(accessToken, null);
    });

    it('Generated access token must be decoded back to get original data', function(){
        var timestamp = new Date().getTime();
        var accessToken = ctCore.createAccessToken(config, USER_ID, timestamp, DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(config, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.equal(accessTokenSet.userId, USER_ID);
        assert.equal(accessTokenSet.timestamp, timestamp);
        assert.deepEqual(accessTokenSet.data, DATA);
    });

    it('Should return an error when submitted access token is invalid', function() {
        var accessToken = 'invalid access token';
        var accessTokenSet = ctCore.getAccessTokenSet(config, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.notEqual(accessTokenSet.err, null);
        assert.strictEqual(accessTokenSet.err.err, 'Bad accessToken');
    });

    it('Should return an error when trying to decode with invalid firm key', function(){
        var accessToken = ctCore.createAccessToken(config, USER_ID, new Date().getTime(), DATA);
        var accessTokenSet = ctCore.getAccessTokenSet(anotherConfig, accessToken);

        assert.notEqual(accessTokenSet, null);
        assert.notEqual(accessTokenSet.err, null);
        assert.strictEqual(accessTokenSet.err.err, 'Bad firm');
    });
});
