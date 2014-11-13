var assert = require('assert');
var ctCore = require('../cipherTokenCore');

describe('Access token generation', function(){

    it('Should generate access token', function(){
        var config = {
            cipherKey: 'myCipherKey123',
            firmKey:  'myFirmKey123'
        };

        var accessToken = ctCore.createAccessToken(config, 'userId', new Date().getTime(), 'validData');

        assert.notEqual(accessToken, null);
    })

});

