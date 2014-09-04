var debug = require('debug')('ciphertoken-perf');
var crypto = require('crypto');
var assert = require('assert');

var ciphertoken = require('../ciphertoken');

var VALID_CIPHER_KEY = 'myCipherKey123';
var VALID_FIRM_KEY 	 = 'myFirmKey123';
var VALID_USER_ID 	 = 'myUserId123';
var VALID_DATA       = require('./bigdata.json').data;

var INVALID_FIRM_KEY = 'myFirmKey12345';

var perfOps = { create : 'create', check_ts : 'check_ts', check_firm : 'check_firm', read : 'read' };
var perfTypes = { token : 'token', refreshToken : 'refreshToken', accessToken : 'accessToken' };
var perfTasks = [

	{ amount : 100 		, op: perfOps.create, type : perfTypes.refreshToken },
	{ amount : 1000 	, op: perfOps.create, type : perfTypes.refreshToken },
	{ amount : 10000 	, op: perfOps.create, type : perfTypes.refreshToken },
	{ amount : 50000 	, op: perfOps.create, type : perfTypes.refreshToken },
	{ amount : 100000 	, op: perfOps.create, type : perfTypes.refreshToken },

	{ amount : 100		, op: perfOps.create, type : perfTypes.accessToken },
	{ amount : 1000 	, op: perfOps.create, type : perfTypes.accessToken },
	{ amount : 10000 	, op: perfOps.create, type : perfTypes.accessToken },
	{ amount : 50000 	, op: perfOps.create, type : perfTypes.accessToken },
	{ amount : 100000 	, op: perfOps.create, type : perfTypes.accessToken },

	{ amount : 100 		, op: perfOps.check_ts, type : perfTypes.accessToken },
	{ amount : 1000 	, op: perfOps.check_ts, type : perfTypes.accessToken },
	{ amount : 10000 	, op: perfOps.check_ts, type : perfTypes.accessToken },

	{ amount : 100 		, op: perfOps.check_firm, type : perfTypes.accessToken },
	{ amount : 1000 	, op: perfOps.check_firm, type : perfTypes.accessToken },
	{ amount : 10000 	, op: perfOps.check_firm, type : perfTypes.accessToken },

	{ amount : 100 		, op: perfOps.read, type : perfTypes.accessToken },
	{ amount : 1000 	, op: perfOps.read, type : perfTypes.accessToken },
	{ amount : 10000 	, op: perfOps.read, type : perfTypes.accessToken },

	{}
]

var tokens = [];
function generateTokens(p_amount){
	for(var f=0;f<p_amount;f++){
		tokens[tokens.length] = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
	}
}

function runPerfTask(perfTask){
	var cToken,refToken,accToken;
	var t1 = new Date().getTime();
	debug('running perfTask', perfTask);
	for(var f=0;f<perfTask.amount;f++){
		cToken = ciphertoken.create(VALID_CIPHER_KEY,VALID_FIRM_KEY);
		switch (perfTask.type){
			case perfTypes.refreshToken :
				refToken = cToken.createRefreshToken();
				break;
			case perfTypes.accessToken :
				accToken = cToken.createAccessToken(VALID_USER_ID,new Date().getTime(), VALID_DATA);
				switch (perfTask.op){
					case perfOps.check_ts:
						cToken.getAccessTokenExpiration(accToken);
						break;
					case perfOps.check_firm:
						cToken.checkAccessTokenFirm(accToken);
						break;
					case perfOps.read:
						cToken.getAccessTokenSet(accToken);
						break;
				}
				break;
		}
	}
	debug('result['+(new Date().getTime()-t1)+']');
}

for(var f=0;f<perfTasks.length;f++){	
	runPerfTask( perfTasks[f] );
}
