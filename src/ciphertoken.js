var debug = require('debug')('ciphertoken');
var crypto = require('crypto');

var CreateCipherToken = function (cipherKey, firmKey, options){
	'use strict';

	function CipherToken(){ }

    var SEPARATOR = '_`$ep@r4t0r`_';
	var _ERRORS = {
		cipherkey_required : { err:'cipherkey_required',des:'cipherKey parameter is mandatory' },
		firmkey_required : { err:'firmkey_required',des:'firmKey parameter is mandatory' },
		bad_firm : { err:'bad_firm',des:'firm is not valid' },
		bad_accesstoken : { err:'bad_accesstoken', des:'accesstoken is not valid' },
		accesstoken_expired : { err:'accesstoken_expired',des:'accesstoken has expired it must be renewed' },
        serialization_error: { err: 'serialization_error', des: 'error during data serialization'},
        unserialization_error: { err: 'unserialization_error', des: 'error during data deserialization'}
	}

	//
	// Mandatory parameters
	//

	if(!cipherKey) throw _ERRORS.cipherkey_required;
	function getCipherKey (){
		return cipherKey;
	}

	if(!firmKey) throw _ERRORS.firmkey_required;
	function getFirmKey (){
		return firmKey;
	}


    function serialize(data){
        try {
            return JSON.stringify(data);
        } catch (e) {
            debug('Serialization error', e);
            throw _ERRORS.serialization_error;
        }
    }

    function unserialize(data) {
        try {
            return JSON.parse(data);
        } catch (e) {
            debug('Serialization error', e);
            throw _ERRORS.unserialization_error;
        }
    }
	//
	// Options
	//

	// default settings
	var settings = {
		cipher_algorithm : 'aes-256-cbc',
		hmac_algorithm : 'md5',
		hmac_digest_encoding : 'hex',
		plain_encoding : 'utf8',
		token_encoding : 'base64',
		accessTokenExpirationMinutes : 90,
		enableSessionId: false
	}

	for ( var p in options ){
		settings[p] = options[p];
	}

	//
	// Private methods
	//

	function firmAccessToken (consumerId, timestamp, serializedData, sessionId){
		if (settings.enableSessionId) {
			return crypto.createHmac(settings.hmac_algorithm,getFirmKey()).update(consumerId+timestamp+serializedData+sessionId).digest(settings.hmac_digest_encoding);
		}
		return crypto.createHmac(settings.hmac_algorithm,getFirmKey()).update(consumerId+timestamp+serializedData).digest(settings.hmac_digest_encoding);
	}

	function cipherAccessTokenSet(accessTokenSet){
		var cipher = crypto.createCipher( settings.cipher_algorithm, getCipherKey());
		var data = cipher.update(accessTokenSet.join(SEPARATOR), settings.plain_encoding, settings.token_encoding);
		return  standarizeToken(data+cipher.final(settings.token_encoding));
	}

	function decipherAccessToken (accessToken){
		var decipher = crypto.createDecipher( settings.cipher_algorithm, getCipherKey() );
		var data = decipher.update(accessToken, settings.token_encoding, settings.plain_encoding);
		if ( !data ) return null;
		data =  ( data + decipher.final(settings.plain_encoding) ).split(SEPARATOR);
        data[2] = unserialize(data[2]);
        return data;
	}

	function getSessionId(accessToken) {
		var accessTokenSet = decipherAccessToken(accessToken);
		return accessTokenSet[3]
	}

	function checkAccessTokenFirm(accessToken){
		var accessTokenSet = decipherAccessToken(accessToken);
        var serializedData = serialize(accessTokenSet[2]);

		if (settings.enableSessionId) {
			var sessionId = getSessionId(accessToken);
			debug('checkAccessTokenFirm', accessTokenSet, firmAccessToken(accessTokenSet[0], accessTokenSet[1], serializedData, sessionId));

			return (firmAccessToken(accessTokenSet[0], accessTokenSet[1], serializedData, sessionId) === accessTokenSet[4]);
		}
		debug('checkAccessTokenFirm', accessTokenSet, firmAccessToken(accessTokenSet[0], accessTokenSet[1], serializedData ));
		return (firmAccessToken(accessTokenSet[0], accessTokenSet[1], serializedData) === accessTokenSet[3]);
	}

	function hasAccessTokenExpired(accessToken){
		var accessTokenSet = decipherAccessToken(accessToken);
		return ((new Date().getTime()-accessTokenSet[1]) > settings.accessTokenExpirationMinutes*60*1000);
	}

	function standarizeToken(token){
		return token.
			replace(/\+/g, '-'). 	// Convert '+' to '-'
			replace(/\//g, '_'). 	// Convert '/' to '_'
			replace(/=+$/, '') 		// Remove ending '='
		;
	}

	//
	// Public members
	//

	CipherToken.prototype.ERRORS = _ERRORS;

	CipherToken.prototype.createRefreshToken = function (){
		return standarizeToken( crypto.randomBytes(100).toString(settings.token_encoding) );
	}

	CipherToken.prototype.createAccessToken = function (consumerId, timestamp, data){
		if(!timestamp) timestamp = new Date().getTime();
        data = data || {};
		if (settings.enableSessionId){
			var sessionId = crypto.randomBytes(20);
			return cipherAccessTokenSet([consumerId, timestamp, serialize(data), sessionId, firmAccessToken(consumerId, timestamp, serialize(data), sessionId)]);
		}
		return cipherAccessTokenSet([consumerId, timestamp, serialize(data), firmAccessToken(consumerId, timestamp, serialize(data))]);
	}

	CipherToken.prototype.checkAccessTokenFirm = function (accessToken){
		return checkAccessTokenFirm(accessToken);
	}

	CipherToken.prototype.getAccessTokenSet = function (accessToken){
		var tokenSet = {};
		var token = decipherAccessToken(accessToken);
		if ( !token ) {
			tokenSet.err = _ERRORS.bad_accesstoken;
		}
		else if ( !checkAccessTokenFirm(accessToken) ) {
			tokenSet.err = _ERRORS.bad_firm;
		}
		else {

			if ( hasAccessTokenExpired(accessToken) ) {
				tokenSet.err = _ERRORS.accesstoken_expired;
			}

			if (settings.enableSessionId) {
				tokenSet = { consummerId : token[0], timestamp : token[1], data: token[2], sessionId: token[3] };
			} else {
				tokenSet = { consummerId : token[0], timestamp : token[1], data: token[2]};
			}
		}
		return tokenSet;
	}

	CipherToken.prototype.getAccessTokenExpiration = function (accessToken){
		var result = { expired : hasAccessTokenExpired(accessToken) };
		if ( !checkAccessTokenFirm(accessToken) ) {
			result.err = _ERRORS.bad_firm;
		}
		return result;
	}
	return new CipherToken();
};

module.exports = { create : CreateCipherToken }
