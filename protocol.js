var protocol = {}

protocol.port = 6481;
protocol.rsaKeyLength = 2048 / 8;
protocol.aesMethod = 'aes-256-cbc';
protocol.aesKeyLength = 32;
protocol.aesIVLength = 16;

protocol.version = 1;

protocol.sourceBlockLength = 256;
protocol.commandBlockLength = 256;
protocol.headerLength = protocol.sourceBlockLength + 8 * protocol.commandBlockLength;

protocol.magic = [0xAA, 0xBB, 0xCC, 0xDD];
protocol.commandPut = 1;
protocol.commandRelay = 2;
protocol.commandAck = 4;

protocol.commandIndex = 4;
protocol.commandSize = 1;
protocol.commandDataOffset = protocol.commandIndex + protocol.commandSize;

protocol.userSize = 32;
protocol.addressSize = 18;
protocol.packageSize = 32;

protocol.getMessageSize = function(byteLength) {
	var l = Math.log(byteLength) / Math.log(2);
	return Math.pow(2, Math.ceil((l - 4) / 2) * 2 + 4);
};

module.exports = protocol;


//MESSAGE:
// - begin source block (256 bytes -> RSA-2048)
//     1 byte protocol version
//     1 byte message type
//    32 byte symmetric key for transport container
//     4 byte symmetric iv for transport container
// - end source block
// - begin encrypted transport container
//    - begin header: 8 x 256 bytes
//      command block   (256 bytes -> RSA-2048)
//        4 byte magic token (0xaabbccdd)
//        1 byte command (put = 1, relay = 2, ack = 4)
//        case put:       32 byte user hash, 16 byte IPv6 + 2 byte port number (ack)
//        case relay:     16 byte IPv6 + 2 byte port number
//        case ack:       32 byte user hash, 32 byte package hash
//    - end header
//    - payload (size: 2^(2n+4) bytes with 0 >= n <= 10)
// - end encrypted transport container
//
// Node receives message
// - decrypt source block
// - check protocol version
// - decrypt transport container
// - decrypt next command block
// IF COMMAND BLOCK IS VALID (compare 4-byte token)
//    - handle command (relay-only nodes only process RELAY commands and drop everything else)
//      - PUT:
//          - read user hash
//          - generate package hash
//          - store payload if it does not exist yet (goto RELAY)
//          - generate ACK payload
//          - replace message payload with ACK payload in transport container
//      - RELAY:  read target address
//      - ACK:    store ack message for client
//
//    - shift source blocks left and pad right with random bytes
//    - encrypt transport container symmetrically
//    - encrypt transport key asymmetrically with public key of target
//    - join new source block and transport container
//    - send to target node
// IF COMMAND BLOCK IS INVALID -> drop!
