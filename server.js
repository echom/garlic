var http = require('http');
var fs = require('fs')
var NodeRSA = require('node-rsa');
var crypto = require('crypto');
var protocol = require('./protocol');
var stream = require('stream');
var MultiStream = require('multistream');
var url = require("url");

var key;
var port = protocol.port;

(function setup() {
	var nrsa,
		privateKey,
		publicKey;
	if(!fs.existsSync('./key.pem')) {
		nrsa = new NodeRSA();
		nrsa.generateKeyPair();
		privateKey = nrsa.exportKey('pkcs1-private');
		publicKey = nrsa.exportKey('pkcs1-public');
		fs.writeFileSync('./key.pem', privateKey);
		fs.writeFileSync('./pub.pem', publicKey);
	}
	key = new NodeRSA(fs.readFileSync('key.pem'));
})();

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
	return ;
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
		commandBlock = data.slice(0, protocol.cbLength);
		console.log(commandBlock.length);
		try {
			commandBlock = key.decrypt(commandBlock);
		} catch(e) {
			console.log("invalid message", e);
			resIn.end();
			return;
		}

		if (commandBlock[0] == protocol.version) {
			command = commandBlock[1];
			aesKey = commandBlock.slice(protocol.cbAesKeyStart, protocol.cbAesKeyEnd);
			aesIV = commandBlock.slice(protocol.cbAesIvStart, protocol.cbAesIvEnd);
			userHash = commandBlock.slice(protocol.cbUserHashStart, protocol.cbUserHashEnd);
			payload = data.slice(protocol.headerLength);

			chunks = [];
			var aesStream = crypto.createDecipheriv(protocol.aesMethod, aesKey, aesIV);
			aesStream.on('data', function(chunk) { chunks.push(chunk); });
			aesStream.on('end', function() {
				payload = Buffer.concat(chunks);

				//PUT
				if(command == protocol.commandPut) {
					payload = putMessage(userHash, protocol.hash(payload), payload);
				}

				if(command == protocol.commandAck) {
					ackMessage(userHash, payload);
				} else {
					//RELAY
					var nextTargetLength = commandBlock[protocol.cbTailStart];
					if(nextTargetLength > protocol.maxUrlLength) {
						console.log("url too long, dropping");
						return;
					}

					nextTarget = commandBlock.slice(protocol.cbTailStart + 1, protocol.cbTailStart + nextTargetLength + 1).toString('utf-8');
					nextTarget = url.parse(nextTarget);
					var reqOut = http.request({ host: nextTarget.host, port: nextTarget.port, method: 'PUT' });

					var streams = [];
					for(i = 1; i < protocol.cbCount; i++) {
						streams.push(function() {
							var aesStream = crypto.createDecipheriv(protocol.aesMethod, aesKey, aesIV);
							aesStream.end(data.slice(i*protocol.cbLength, (i+1)*protocol.cbLength));
							return aesStream;
						});
					}
					streams.push(function() {
						var s = new stream.PassThrough();
						s.end(crypto.randomBytes(protocol.cbLength));
						return s;
					});
					streams.push(function() {
						var s = new stream.PassThrough();
						s.end(payload);
						return s;
					});

					MultiStream(streams).pipe(reqOut, { end: false });
				}
			});
		} else {
			console.log("unsupported protocol version");
		}
		resIn.end();
	});
}

function putMessage(userHash, packageHash, payload) {
	var ackPayload = payload.slice(0, protocol.plAckLength);
	var putPayload = payload.slice(protocol.plAckLength);

	console.log("putting message for " + userHash.toString());
	console.log("message: " + putPayload.toString());

	return ackPayload;
}

function ackMessage(userHash, payload) {
	console.log("acknowledging message for " + userHash.toString());
}

server.listen(protocol.port, 'localhost', function() {
	console.log("Garlic listening on: http://localhost:%s", port);
});
