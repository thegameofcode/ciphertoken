var assert = require('assert');
var ctCore = require('../cipherTokenCore');

const USER_ID = 'userId';
const DATA = 'validData';

var config = {
    cipherKey: 'myCipherKey123',
    firmKey:  'myFirmKey123'
};

describe.only('Access token generation', function(){

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

});

