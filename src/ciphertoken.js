var debug = require('debug')('ciphertoken');
var crypto = require('crypto');

var createCipherToken = function (cipherKey, firmKey, options) {
	'use strict';

	function CipherToken () {}

	var _ERRORS = {
		cipherkey_required : { err:'cipherkey_required',des:'cipherKey parameter is mandatory' },
		firmkey_required : { err:'firmkey_required',des:'firmKey parameter is mandatory' },
		bad_firm : { err:'bad_firm',des:'firm is not valid' },
		bad_accesstoken : { err:'bad_accesstoken', des:'accesstoken is not valid' },
		accesstoken_expired : { err:'accesstoken_expired',des:'accesstoken has expired it must be renewed' },
		serialization_error: { err: 'serialization_error', des: 'error during data serialization'},
		unserialization_error: { err: 'unserialization_error', des: 'error during data deserialization'}
	};

	//
	// Mandatory parameters
	//

	if(!cipherKey) throw _ERRORS.cipherkey_required;
	if(!firmKey) throw _ERRORS.firmkey_required;


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
		accessTokenExpirationMinutes : 90
	};

	for ( var p in options ) {
		settings[p] = options[p];
	}

	//
	// Private methods
	//

	function serialize (data) {
		try {
			return JSON.stringify(data);
		} catch (e) {
			debug('Serialization error', e);
			throw _ERRORS.serialization_error;
		}
	}

	function unserialize (data) {
		try {
			return JSON.parse(data);
		} catch (e) {
			debug('Serialization error', e);
			throw _ERRORS.unserialization_error;
		}
	}

	function firmAccessToken (consumerId, timestamp, serializedData) {
		return crypto.createHmac(settings.hmac_algorithm, firmKey).
			update(consumerId + timestamp + serializedData).
			digest(settings.hmac_digest_encoding);
	}

	function cipherAccessTokenSet (accessTokenSet) {
		var cipher = crypto.createCipher( settings.cipher_algorithm, cipherKey );
		var data = cipher.update(serialize(accessTokenSet), settings.plain_encoding, settings.token_encoding);
		return  standarizeToken(data + cipher.final(settings.token_encoding));
	}

	function decipherAccessToken (accessToken) {
		var decipher = crypto.createDecipher( settings.cipher_algorithm, cipherKey );
		var data = decipher.update(accessToken, settings.token_encoding, settings.plain_encoding);
		if ( !data ) return null;
		data =  unserialize( data + decipher.final(settings.plain_encoding) );
        return data;
	}

	function checkAccessTokenFirm (accessTokenSet) {
		var serializedData = serialize(accessTokenSet.data);
		var firm = firmAccessToken(accessTokenSet.consumerId, accessTokenSet.timestamp, serializedData);
		debug('checkAccessTokenFirm: accessTokenSet.firm=', accessTokenSet.firm, ', firm=', firm);
		return (firm === accessTokenSet.firm);
	}

	function hasAccessTokenExpired (accessTokenSet) {
		return ((new Date().getTime() - accessTokenSet.timestamp) > settings.accessTokenExpirationMinutes * 60 * 1000);
	}

	function standarizeToken (token) {
		return token.
			replace(/\+/g, '-').    // Convert '+' to '-'
			replace(/\//g, '_').    // Convert '/' to '_'
			replace(/=+$/, '')      // Remove ending '='
		;
	}

	//
	// Public members
	//

	CipherToken.prototype.ERRORS = _ERRORS;

	CipherToken.prototype.createRefreshToken = function () {
		return standarizeToken( crypto.randomBytes(100).toString(settings.token_encoding) );
	};

	CipherToken.prototype.createAccessToken = function (consumerId, timestamp, data) {
		if(!timestamp) timestamp = new Date().getTime();

		var serializedData = serialize(data || {});
		var firm = firmAccessToken(consumerId, timestamp, serializedData);

		var accessTokenSet = {
			consumerId  : consumerId,
			timestamp   : timestamp,
			data        : data,
			firm        : firm
		};

		return cipherAccessTokenSet(accessTokenSet);
	};

	CipherToken.prototype.checkAccessTokenFirm = function (accessToken) {
		var accessTokenSet = decipherAccessToken(accessToken);
		return checkAccessTokenFirm(accessTokenSet);
	};

	CipherToken.prototype.getAccessTokenSet = function (accessToken) {
		var tokenSet = {};
		var token = decipherAccessToken(accessToken);

		if ( !token ) {
			tokenSet.err = _ERRORS.bad_accesstoken;

		} else if ( !checkAccessTokenFirm(token) ) {
			tokenSet.err = _ERRORS.bad_firm;

		} else if ( hasAccessTokenExpired(token) ) {
			tokenSet.err = _ERRORS.accesstoken_expired;

		} else {
			tokenSet = token;
			delete tokenSet.firm;
		}

		return tokenSet;
	};

	CipherToken.prototype.getAccessTokenExpiration = function (accessToken) {
		var accessTokenSet = decipherAccessToken(accessToken);
		var result = { expired : hasAccessTokenExpired(accessTokenSet) };
		if ( !checkAccessTokenFirm(accessTokenSet) ) {
			result.err = _ERRORS.bad_firm;
		}
		return result;
	};

	return new CipherToken();
};

module.exports = { create : createCipherToken };
