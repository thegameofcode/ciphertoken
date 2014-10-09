var debug = require('debug')('ciphertoken-test');
var assert = require('assert');

var ciphertoken = require('../ciphertoken');

var VALID_CIPHER_KEY = 'myCipherKey123';
var VALID_FIRM_KEY 	 = 'myFirmKey123';
var VALID_USER_ID 	 = 'myUserId123';
var VALID_DATA       = {random: 1, testkey: "as__df", va__l: "dadsfa"};

var INVALID_FIRM_KEY = 'myFirmKey12345';

describe('# Creation', function() {

	it('CipherToken creation ok', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		assert.notEqual(cToken,null);
	});

	it('CipherToken creation with no cipher key error', function() {
		try {
			var cToken = ciphertoken.create();
		}
		catch (err) {
			debug('creation error no cipher key', err);
			assert.notEqual(err,null);
		}
	});

	it('CipherToken creation with no hmac key error', function() {
		try {
			var cToken = ciphertoken.create(VALID_CIPHER_KEY);
		}
		catch (err) {
			debug('Creation error no hmac key', err);
			assert.notEqual(err,null);
		}
	});

});

describe('# refreshToken', function() {

	it('refreshToken creation ok', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		assert.notEqual(cToken.createRefreshToken(),null);
	});

});

describe('# accessToken', function() {

	it('accessToken creation ok', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var accessToken = cToken.createAccessToken(VALID_USER_ID,new Date().getTime(), VALID_DATA);
		debug('accessToken creation ok', accessToken);
		assert.notEqual(accessToken,null);
	});

	it('accessToken get a set ok', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var timestamp = new Date().getTime();
		var accessToken = cToken.createAccessToken(VALID_USER_ID,timestamp, VALID_DATA);
		var accessTokenSet = cToken.getAccessTokenSet(accessToken);
		debug('accessToken get a set ok', accessTokenSet);
		assert.notEqual(accessTokenSet,null);
		assert.equal(accessTokenSet.consumerId,VALID_USER_ID);
		assert.equal(accessTokenSet.timestamp,timestamp);
		assert.deepEqual(accessTokenSet.data,VALID_DATA);
	});

	it('accessToken get a set with invalid token', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var accessToken = 'invalid access token';
		var accessTokenSet = cToken.getAccessTokenSet(accessToken);
		debug('accessToken get a set with invalid token', accessTokenSet);
		assert.notEqual(accessTokenSet,null);
		assert.notEqual(accessTokenSet.err, null);
		assert.strictEqual(accessTokenSet.err.err, 'bad_accesstoken');
	});

	it('accessToken check correct timestamp', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var accessToken = cToken.createAccessToken(VALID_USER_ID,new Date().getTime());
		debug('accessToken check correct timestamp', accessToken);
		assert.equal( cToken.getAccessTokenExpiration( accessToken ).expired, false );
	});

	it('accessToken check incorrect timestamp', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var refreshToken = cToken.createRefreshToken();
		var accessToken = cToken.createAccessToken(VALID_USER_ID,new Date().getTime()-999999);
		debug('accessToken check incorrect timestamp', accessToken);
		assert.equal( cToken.getAccessTokenExpiration( accessToken ).expired, false );
	});

	it('accessToken check correct firm', function() {
		var cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var refreshToken = cToken.createRefreshToken();
		var accessToken = cToken.createAccessToken(VALID_USER_ID,new Date().getTime(), VALID_DATA);
		debug('accessToken check correct firm', accessToken);
		assert.equal( cToken.checkAccessTokenFirm( accessToken ), true );
	});

	it('accessToken check incorrect firm', function() {
		var cToken1 = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		var accessToken1 = cToken1.createAccessToken(VALID_USER_ID,new Date().getTime());

		var cToken2 = ciphertoken.create(VALID_CIPHER_KEY,INVALID_FIRM_KEY);
		var accessToken2 = cToken2.createAccessToken(VALID_USER_ID,new Date().getTime());

		assert.equal( cToken1.checkAccessTokenFirm( accessToken2 ), false );
		assert.equal( cToken2.checkAccessTokenFirm( accessToken1 ), false );

	});

/**
	TODO TEST COMMON ATTACKS

	it('attempted accessToken modification', function() {

	});

**/
	

});








