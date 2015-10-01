var http = require('http');
var fs = require('fs')
var ursa = require('ursa');
var crypto = require('crypto');
var protocol = require('./protocol');

var pubKeyCache = {
	'0000:0000:0000:0000:0000:0000:0000:0001': ursa.createPublicKey(fs.readFileSync('./pub.pem'))
};

function test() {
	var payload = new Buffer("hello world");
	var nextTarget = new Buffer([
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		(protocol.port >> 8) & 0xff,
		protocol.port & 0xff
	]);
	var nextTargetAddress = '';
	var nextTargetPort = nextTarget[16] * 256 + nextTarget[17];
	for (i = 0; i < 8; i++) {
		nextTargetAddress += nextTarget.toString('hex', 2 * i, 2 * (i + 1));
		if (i < 7) nextTargetAddress += ':';
	}

	var commandBlock = Buffer.concat([
		new Buffer(protocol.magic),
		new Buffer(protocol.commandPut),
		crypto.randomBytes(protocol.userSize),
		nextTarget
	]);

	var transportContainer = Buffer.concat([
		commandBlock,
		crypto.randomBytes(7 * protocol.commandBlockLength),
		payload
	]);
	var aesKey = crypto.randomBytes(protocol.aesKeyLength);
	var aesIV = crypto.randomBytes(protocol.aesIVLength);

	var sourceBlock = Buffer.concat([
		new Buffer([protocol.version, 0]),
		aesKey,
		aesIV
	]);
	var targetKey = pubKeyCache[nextTargetAddress];

	sourceBlock = targetKey.encrypt(sourceBlock);
	console.log(nextTargetAddress, nextTargetPort);
	var reqOut = http.request({
		host: nextTargetAddress,
		port: nextTargetPort,
		method: 'PUT'
	});

	reqOut.write(sourceBlock);
	aesStream = crypto.createCipheriv(protocol.aesMethod, aesKey, aesIV);
	aesStream.pipe(reqOut);
	aesStream.write(transportContainer);
	aesStream.end();
	reqOut.end();
}

test();
