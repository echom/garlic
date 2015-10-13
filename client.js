var http = require('http');
var fs = require('fs')
var NodeRSA = require('node-rsa');
var crypto = require('crypto');
var protocol = require('./protocol');

var pubKeyCache = {};
pubKeyCache['http://localhost:' + protocol.port] = new NodeRSA(fs.readFileSync('pub.pem'));

function _makeCommand(command, aesKey, aesIV, rsaKey, userHash, nextTarget) {
	var buffers = [];
	buffers.push(new Buffer([protocol.version, protocol.commandPut]));
	buffers.push(aesKey);
	buffers.push(aesIV);
	buffers.push(userHash || new Buffer(32));

	if(command != protocol.commandAck) {
		buffers.push(new Buffer([Buffer.byteLength(nextTarget, 'utf-8')]));
		buffers.push(new Buffer(nextTarget));
	}

	return rsaKey.encrypt(Buffer.concat(buffers));
}

function makePut(aesKey, aesIV, userHash, rsaKey, nextTarget) {
	return _makeCommand(protocol.commandPut, aesKey, aesIV, rsaKey, userHash, nextTarget);
}
function makeRelay(aesKey, aesIV, rsaKey, nextTarget) {
	return _makeCommand(protocol.commandRelay, aesKey, aesIV, rsaKey, null, nextTarget);
}
function makeAck(aesKey, aesIV, userHash, rsaKey) {
	return _makeCommand(protocol.commandAck, aesKey, aesIV, rsaKey, userHash);
}

function getTargetRSA(target) { return pubKeyCache[target]; }

function createMessage(payload, sender, recipient) {
	var ack = Buffer.concat([
		protocol.hash(payload),
		new Buffer(256 - 32) //pure padding while we don't encrypt the ack;
	]);

	var messageSize = protocol.getMessageSize(payload.length);
	payload = Buffer.concat([payload, crypto.randomBytes(messageSize - payload.length)]);

	return {
		payload: payload,
		sender: sender,
		recipient: recipient,
		target: null,
		data: ack,
		commands: []
	};
}


function onionize(message, command, target, cb) {
	var targetBytes = new Buffer(target, 'utf-8');
	var aesKey = crypto.randomBytes(protocol.aesKeyLength);
	var aesIV = crypto.randomBytes(protocol.aesIVLength)
	var targetRSA = getTargetRSA(target);

	message.commands.unshift(_makeCommand(
		command, aesKey, aesIV, targetRSA,
		command == protocol.commandAck ? message.sender : message.recipient,
		message.target
	));
	var ncommands = message.commands.length,
		processing = ncommands,
		aes;
	for(var i = 0; i < ncommands; i++) {
		(function(ii) {
			var chunks = [],
				aesStream = crypto.createCipheriv(protocol.aesMethod, aesKey, aesIV);

			aesStream.on('data', function(chunk) { chunks.push(chunk); });
			aesStream.on('end', function() {
				console.log('aesstream end');
				message.commands[ii] = Buffer.concat(chunks);
				processing--;
				if(processing == 0) {
					chunks = [];
					aesStream = crypto.createCipheriv(protocol.aesMethod, aesKey, aesIV);
					aesStream.on('data', function(chunk) {chunks.push(chunk) });
					aesStream.on('end', function() {
						message.data = Buffer.concat(chunks);
						cb();
					});
					message.target = target;

					if(command == protocol.commandPut) {
						message.data = Buffer.concat([message.data, message.payload]);
					}
					aesStream.end(message.data);
				}
			});
			aesStream.end(message.commands[ii]);
		})(i);
	}
}

function test() {
	var message = createMessage(
		new Buffer( "hello world", 'utf-8'),
		crypto.randomBytes(protocol.userHashLength),
		crypto.randomBytes(protocol.userHashLength),
		'http://localhost:' + protocol.port
	);
	onionize(message, protocol.commandAck, 'http://localhost:' + protocol.port, function() {
		console.log("onionize ack");
		onionize(message, protocol.commandPut, 'http://localhost:' + protocol.port, function() {
			console.log("onionize put");
			var reqOut = http.request({
				host: 'localhost',
				port: protocol.port,
				method: 'PUT',
				headers: { 'Content-Type': 'application/octet-stream' }
			});
			var ncommands = message.commands.length,
				i = 0;
			for(; i < ncommands; i++) {
				reqOut.write(message.commands[i]);
			}
			for(; i < protocol.cbCount; i++) {
				reqOut.write(crypto.randomBytes(protocol.cbLength));
			}

			reqOut.write(message.data);
			reqOut.end();
		});
	});
}







test();
