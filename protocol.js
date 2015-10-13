var crypto = require("crypto");

var protocol = {}

protocol.port = 6481;
protocol.rsaKeyLength = 2048 / 8;
protocol.rsaPadding = 11;
protocol.aesMethod = 'aes-256-cbc';
protocol.aesKeyLength = 32;
protocol.aesIVLength = 16;

protocol.version = 1;

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
    hash = crypto.createHash("sha256");
    hash.update(data);
	return hash.digest();
}

module.exports = protocol;

//MESSAGE:
//    - begin header: 8 x 256 bytes
//      command block   (256 bytes -> RSA-2048, contents: 245 bytes)
//        1 byte protocol version
//        1 byte command (put = 1, relay = 2, ack = 4)
//       32 byte symmetric key for transport container
//        4 byte symmetric iv for transport container
//       32 byte user hash (empty in case of relay)
//        case put/relay:  1 byte URL-length, 172 byte URL (utf-8 encoded)
//    - end header
//    - payload
//
// Node receives message
// - decrypt first command block (node's private RSA key)
//		- check protocol version
//		- decrypt remaining command blocks and payload 1 by 1 with contained AES parameters
//		- handle command (relay-only nodes only process RELAY commands and drop everything else)
//      - PUT:
//          - read user hash
//          - generate package hash
//          - store payload if it does not exist yet (goto RELAY)
//          - generate ACK payload
//          - replace message payload with ACK payload in transport container
//      - RELAY:  read target address
//      - ACK:    store ack message for client
//
//    - shift command blocks left and pad right with random bytes
//    - send to target node
