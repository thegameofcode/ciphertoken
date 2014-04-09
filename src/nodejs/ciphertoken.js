var debug = require('debug')('ciphertoken');
var crypto = require('crypto');

var CreateCipherToken = function (cipherKey, firmKey, options){
	'use strict';

	function CipherToken(){ }

	var _ERRORS = {
		cipherkey_required : { err:'cipherkey_required',des:'cipherKey parameter is mandatory' },
		firmkey_required : { err:'firmkey_required',des:'firmKey parameter is mandatory' },
		bad_firm : { err:'bad_firm',des:'firm is not valid' },
		accesstoken_expiration_required : { err:'accesstoken_expiration_required',des:'accesstoken expiration value must be a positive integer' }
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
		return (firmAccessToken(accessTokenSet[0], accessTokenSet[1]) === accessTokenSet[2]);
	}

	function checkAccessTokenExpiration(accessToken){
		if(!settings.accessTokenExpirationMinutes) throw _ERRORS.accesstoken_expiration_required;
		var accessTokenSet = decipherAccessToken(accessToken);
		return ((new Date().getTime()-accessTokenSet[1]) < settings.accessTokenExpirationMinutes*60*1000);
	}

	function standarizeToken(token){
		return token.
			replace(/\+/g, '-'). 	// Convert '+' to '-'
			replace(/\//g, '_'). 	// Convert '/' to '_'
			replace(/=+$/, '') 		// Remove ending '='
		;
	}

	//
	// Public methods
	//

	CipherToken.prototype.createRefreshToken = function (){
		return standarizeToken( crypto.randomBytes(100).toString('base64') );
	}

	CipherToken.prototype.createAccessToken = function (consumerId,timestamp){
		var accessTokenSet = [consumerId,timestamp,firmAccessToken(consumerId, timestamp)];
		return cipherAccessTokenSet(accessTokenSet);
	}

	CipherToken.prototype.getAccessTokenSet = function (accessToken){
		var token = decipherAccessToken(accessToken);
		var tokenSet = { consummerId : token[0], timestamp : token[1] };
		if ( !checkAccessTokenFirm(accessToken) ) {
			tokenSet.err = _ERRORS.bad_firm;
		}
		return tokenSet;
	}

	CipherToken.prototype.getAccessTokenExpiration = function (accessToken){
		var result = { expired : !checkAccessTokenExpiration(accessToken) };
		if ( !checkAccessTokenFirm(accessToken) ) {
			result.err = _ERRORS.bad_firm;
		}
		return result;
	}

	return new CipherToken();
};

module.exports = { create : CreateCipherToken }