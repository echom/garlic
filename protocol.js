(function() {
	'use strict';

	var crypto = require("crypto"),
		protocol = {};

	protocol.version = 1;

	protocol.port = 6481;
	protocol.rsaKeyLength = 2048 / 8;
	protocol.rsaPadding = 11;
	protocol.aesMethod = 'aes-256-cbc';
	protocol.aesKeyLength = 32;
	protocol.aesIVLength = 16;

	protocol.cbLength = 256;
	protocol.cbCount = 8;
	protocol.headerLength = protocol.cbCount * protocol.cbLength;
	protocol.urlMaxLength = protocol.cbLength - protocol.rsaPadding - protocol.cbTailStart - 1;
	protocol.userHashLength = 32;
	protocol.packageHashLength = 32;

	protocol.commandPut = 1;
	protocol.commandRelay = 2;
	protocol.commandAck = 4;

	protocol.cbVersionStart = 0;
	protocol.cbVersionEnd = 1;
	protocol.cbCommandStart = protocol.cbVersionEnd;
	protocol.cbCommandEnd = protocol.cbCommandStart + 1;
	protocol.cbAesKeyStart = protocol.cbCommandEnd;
	protocol.cbAesKeyEnd = protocol.cbAesKeyStart + protocol.aesKeyLength;
	protocol.cbAesIvStart = protocol.cbAesKeyEnd;
	protocol.cbAesIvEnd = protocol.cbAesKeyEnd + protocol.aesIVLength;
	protocol.cbUserHashStart = protocol.cbAesIvEnd;
	protocol.cbUserHashEnd = protocol.cbAesIvEnd + protocol.userHashLength;
	protocol.cbTailStart = protocol.cbUserHashEnd;

	protocol.plAckLength = 256;
	protocol.plMinExponent = 10;

	protocol.getMessageSize = function(contentLength) {
		var byteLength = contentLength + protocol.plAckLength;
		var l = Math.max(protocol.plMinExponent, Math.log(byteLength) / Math.log(2));
		return Math.pow(2, Math.ceil(l/2)*2);
	};

	protocol.hash = function(data) {
	    var hash = crypto.createHash("sha256");
	    hash.update(data);
		return hash.digest();
	};

	module.exports = protocol;
})();
