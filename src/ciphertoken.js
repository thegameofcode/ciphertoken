var debug = require('debug')('ciphertoken');
var crypto = require('crypto');

var CreateCipherToken = function (cipherKey, firmKey, options){
	'use strict';

	function CipherToken(){ }

	var _ERRORS = {
		cipherkey_required : { err:'cipherkey_required',des:'cipherKey parameter is mandatory' },
		firmkey_required : { err:'firmkey_required',des:'firmKey parameter is mandatory' },
		bad_firm : { err:'bad_firm',des:'firm is not valid' },
		accesstoken_expired : { err:'accesstoken_expired',des:'accesstoken has expired it must be renewed' }
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

	//
	// Options
	//

	var settings = {
		algorythm : 'aes-256-cbc',
		accessTokenExpirationMinutes : 90
	}

	for ( var p in options ){
		settings[p] = options[p];
	}


	//
	// Private methods
	//

	function firmAccessToken (consumerId, timestamp){
		return crypto.createHmac('md5',getFirmKey()).update(consumerId+timestamp).digest('hex');
	}

	function cipherAccessTokenSet(accessTokenSet){
		var cipher = crypto.createCipher( settings.algorythm, getCipherKey());
		var data = cipher.update(accessTokenSet.join('__'), 'utf8', 'base64');
		return  standarizeToken(data+cipher.final('base64'));
	}

	function decipherAccessToken (accessToken){
		var decipher = crypto.createDecipher( settings.algorythm, getCipherKey() );
		var data = decipher.update(accessToken, 'base64', 'utf8');
		return (data+decipher.final('utf8')).split('__');
	}

	function checkAccessTokenFirm(accessToken){
		var accessTokenSet = decipherAccessToken(accessToken);
debug('checkAccessTokenFirm', accessTokenSet, firmAccessToken(accessTokenSet[0], accessTokenSet[1]));
		return (firmAccessToken(accessTokenSet[0], accessTokenSet[1]) === accessTokenSet[2]);
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
		return standarizeToken( crypto.randomBytes(100).toString('base64') );
	}

	CipherToken.prototype.createAccessToken = function (consumerId,timestamp){
		var accessTokenSet = [consumerId,timestamp,firmAccessToken(consumerId, timestamp)];
		return cipherAccessTokenSet(accessTokenSet);
	}

	CipherToken.prototype.checkAccessTokenFirm = function (accessToken){
		return checkAccessTokenFirm(accessToken);
	}

	CipherToken.prototype.getAccessTokenSet = function (accessToken){
		var token = decipherAccessToken(accessToken);
		var tokenSet = { consummerId : token[0], timestamp : token[1] };
		if ( !checkAccessTokenFirm(accessToken) ) {
			tokenSet.err = _ERRORS.bad_firm;
		}
		else if ( hasAccessTokenExpired(accessToken) ) {
			tokenSet.err = _ERRORS.accesstoken_expired;
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