var http = require('http');
var fs = require('fs')
var NodeRSA = require('node-rsa');
var crypto = require('crypto');
var protocol = require('./protocol');

var pubKeyCache = {};
pubKeyCache['http://localhost:' + protocol.port] = new NodeRSA(fs.readFileSync('pub.pem'));


function test() {
	var message = "hello world";
	var payload = new Buffer(message);
	var payloadSize = Buffer.byteLength(message);
	var messageSize = protocol.getMessageSize(payloadSize);
	var remainderSize = messageSize - payloadSize;

	var nextTargetAddress = 'http://localhost:' + protocol.port;
	var nextTarget = new Buffer(nextTargetAddress, 'utf-8');

	var aesKey = crypto.randomBytes(protocol.aesKeyLength);
	var aesIV = crypto.randomBytes(protocol.aesIVLength);
	var rsaKey = pubKeyCache[nextTargetAddress];

	var commandBlock = Buffer.concat([
		new Buffer([protocol.version, protocol.commandPut]),
		aesKey = crypto.randomBytes(protocol.aesKeyLength),
		aesIV = crypto.randomBytes(protocol.aesIVLength),
		crypto.randomBytes(protocol.userHashLength),
		new Buffer([Buffer.byteLength(nextTargetAddress, 'utf-8')]),
		nextTarget
	]);
	commandBlock = rsaKey.encrypt(commandBlock);
	console.log(commandBlock.length);
	//TODO: encrypt hop command blocks with AES
	var commandGarbage = crypto.randomBytes(7 * protocol.cbLength);

	var reqOut = http.request({
		host: 'localhost',
		port: protocol.port,
		method: 'PUT',
		headers: { 'Content-Type': 'application/octet-stream' }
	});
	var fsOut = fs.createWriteStream("send.bin");

	reqOut.write(commandBlock);
	reqOut.write(commandGarbage);
	fsOut.write(commandBlock);
	fsOut.write(commandGarbage);

	aesStream = crypto.createCipheriv(protocol.aesMethod, aesKey, aesIV);
	aesStream.pipe(reqOut);
	aesStream.pipe(fsOut);
	aesStream.write(payload);
	aesStream.end();
}

test();
