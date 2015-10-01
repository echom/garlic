var http = require('http');
var fs = require('fs')
var ursa = require('ursa');
var crypto = require('crypto');
var protocol = require('./protocol');

var key = ursa.createPrivateKey(fs.readFileSync('./key.pem'));
var port = protocol.port;

var server = http.createServer(function(req, res) {
	switch (req.method) {
		case 'PUT':
			handleMessage(req, res);
			break;
		default:
			break;
	}
	//res.end('It Works!! Path Hit: ' + req.url);
});

function isProtocolValid(version) {
	return version == protocol.version;
}

function handleMessage(reqIn, resIn) {
	var data,
		chunks = [],
		isValid,
		sourceBlock,
		aesKey,
		aesIV,
		aesStream,
		transportContainer,
		commandBlock,
		i,
		nextTarget,
		userHash,
		packageHash,
		command;
	reqIn.on('data', function(chunk) {
		chunks.push(chunk);
	});
	reqIn.on('end', function() {
		data = Buffer.concat(chunks);
		sourceBlock = data.slice(0, protocol.sourceBlockLength);
		sourceBlock = key.decrypt(sourceBlock);

		if (isValid = isProtocolValid(sourceBlock[0])) {
			aesKey = sourceBlock.slice(2, 2 + protocol.aesKeyLength);
			aesIV = sourceBlock.slice(2 + protocol.aesKeyLength, 2 + protocol.aesKeyLength + protocol.aesIVLength);

			chunks = [];
			aesStream = crypto.createDecipheriv(protocol.aesMethod, aesKey, aesIV);
			aesStream.on('data', function(chunk) {
				console.log("chunk");
				chunks.push(chunk);
			});
			aesStream.on('end', function() {
				transportContainer = Buffer.concat(chunks);
				commandBlock = transportContainer.slice(0, protocol.commandBlockLength);
				commandBlock = key.decrypt(commandBlock);

				for (i = 0; i < 4; i++) {
					if (commandBlock[i] != protocol.magic[i]) {
						isValid = false;
						break;
					}
				}
				if (isValid) {
					switch (command = commandBlock[protocol.commandIndex]) {
						case protocol.commandPut:
							userHash = commandBlock.slice(
								protocol.commandDataOffset,
								protocol.commandDataOffset + protocol.userSize
							);
							nextTarget = commandBlock.slice(
								protocol.commandDataOffset + protocol.userSize,
								protocol.commandDataOffset + protocol.userSize + protocol.addressSize
							);
							break;
						case protocol.commandRelay:
							nextTarget = commandBlock.slice(
								protocol.commandDataOffset,
								protocol.commandDataOffset + protocol.addressSize
							);
							break;
						case protocol.commandAck:
							userHash = commandBlock.slice(
								protocol.commandDataOffset,
								protocol.commandDataOffset + protocol.userSize
							);
							packageHash = commandBlock.slice(
								protocol.commandDataOffset + protocol.userSize,
								protocol.commandDataOffset + protocol.userSize + protocol.packageSize
							);
							break;
						default:
							isValid = false;
							break;
					}
				}

				if (isValid) {
					var remainder = data.slice(
						protocol.sourceBlockLength + protocol.commandBlockLength,
						protocol.headerLength
					);
					var payload = data.slice(protocol.headerLength);

					if (command == protocol.commandPut) {
						packageHash = hash(payload);
						payload = putMessage(userHash, packageHash, payload);
					} else if (command == protocol.commandAck)
						ackMessage(userHash, packageHash, payload);
				}

				if (command == protocol.commandPut ||  command = protocol.commandRelay) {
					var nextTargetAddress = '';
					var nextTargetPort = nextTarget[16] * 256 + nextTarget[17];
					for (i = 0; i < 8; i++) {
						nextTargetAddress += nextTarget.toString('hex', 2 * i, 2 * (i + 1));
						if (i < 7) nextTargetAddress += ':';
					}
					transportContainer = Buffer.concat([
						remainder,
						crypto.randomBytes(protocol.commandBlockLength),
						payload
					]);
					aesKey = crypto.randomBytes(protocol.aesKeyLength);
					aesIV = crypto.randomBytes(protocol.aesKeyLength);

					sourceBlock = Buffer.concat([
						new Buffer(protocol.version, 0),
						aesKey,
						aesIV
					]);
					var targetKey = pubKeyCache[nextTargetAddress];
					sourceBlock = targetKey.encrypt(sourceBlock);

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
			});

			aesStream.write(data.slice(protocol.sourceBlockLength));
			aesStream.end();
		}
		resIn.end();
	});
}

function putMessage(userHash, packageHash, payload) {
	console.log("putting message for " + userHash.toString());
}

function ackMessage(userHash, packageHash, payload) {
	console.log("acknowledging message for " + userHash.toString());
}

server.listen(port, '::1', function() {
	console.log("Garlic listening on: http://localhost:%s", port);
});
