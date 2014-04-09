var debug = require('debug')('ciphertoken');
var crypto = require('crypto');

var CreateCipherToken = function (cipherKey, hmacKey, options){
	'use strict';

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
		accessTokenExpirationMinutes : 90
	}

	for ( var p in options ){
		settings[p] = options[p];
	}

	function firmAccessToken (refreshToken, userId, timestamp){
		return crypto.createHmac('md5',getHmacKey()).update(refreshToken+userId+timestamp).digest('hex');
	}

	function cipherAccessTokenSet(accessTokenSet){
		var cipher = crypto.createCipher( 'aes-256-cbc', getCipherKey());
		var data = cipher.update(accessTokenSet.join('__'), 'utf8', 'base64');
		return  standarizeToken(data+cipher.final('base64'));
	}

	function decipherAccessToken (accessToken){
		var decipher = crypto.createDecipher( 'aes-256-cbc', getCipherKey() );
		var data = decipher.update(accessToken, 'base64', 'utf8');
		return (data+decipher.final('utf8')).split('__');
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

	function CipherToken(){ }

	CipherToken.prototype.createRefreshToken = function (){
		return standarizeToken( crypto.randomBytes(100).toString('base64') );
	}

	CipherToken.prototype.createAccessToken = function (refreshToken,userId,timestamp){
		var accessTokenSet = [userId,timestamp,firmAccessToken(refreshToken, userId, timestamp)];
		return cipherAccessTokenSet(accessTokenSet);
	}

	CipherToken.prototype.getAccessTokenSet = function (refreshToken,accessToken){
		this.checkAccessTokenFirm(refreshToken,accessToken);
		this.checkAccessTokenExpiration(accessToken);
		return decipherAccessToken(accessToken);
	}

	CipherToken.prototype.checkAccessTokenFirm = function (refreshToken,accessToken){
		var accessTokenSet = decipherAccessToken(accessToken);
		return (firmAccessToken(refreshToken, accessTokenSet[0], accessTokenSet[1]) === accessTokenSet[2]);
	}

	CipherToken.prototype.checkAccessTokenExpiration = function (accessToken){
		if(!settings.accessTokenExpirationMinutes) throw _ERRORS.accesstoken_expiration_required;
		var accessTokenSet = decipherAccessToken(accessToken);
		return ((new Date().getTime()-accessTokenSet[1]) < settings.accessTokenExpirationMinutes*60*1000);
	}

	return new CipherToken();
};

module.exports = { create : CreateCipherToken }