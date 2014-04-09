var debug = require('debug')('ciphertoken');
var crypto = require('crypto');

var CreateCipherToken = function (cipherKey, hmacKey, options){
	'use strict';

	function CipherToken(){ }

	//
	// Private
	//
	var _ERRORS = {
		cipherkey_required : { err:'cipherkey_required',des:'cipherKey parameter is mandatory' },
		hmackey_required : { err:'hmackey_required',des:'hmacKey parameter is mandatory' },
		accesstoken_expiration_required : { err:'accesstoken_expiration_required',des:'accesstoken expiration value must be a positive integer' }
	}

	if(!cipherKey) throw _ERRORS.cipherkey_required;
	function getCipherKey (){
		return cipherKey;
	}

	if(!hmacKey) throw _ERRORS.hmackey_required;
	function getHmacKey (){
		return hmacKey;
	}

	var settings = {
		algorythm : 'aes-256-cbc',
		accessTokenExpirationMinutes : 90
	}

	for ( var p in options ){
		settings[p] = options[p];
	}

	function firmAccessToken (consumerId, timestamp){
		return crypto.createHmac('md5',getHmacKey()).update(consumerId+timestamp).digest('hex');
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
		checkAccessTokenFirm(accessToken);
		return decipherAccessToken(accessToken);
	}

	CipherToken.prototype.checkAccessTokenExpiration = function (accessToken){
		checkAccessTokenFirm(accessToken);
		return checkAccessTokenExpiration(accessToken);
	}

	return new CipherToken();
};

module.exports = { create : CreateCipherToken }