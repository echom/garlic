var fs = require('fs'),
	NodeRSA = require('node-rsa');

nrsa = new NodeRSA();
nrsa.generateKeyPair();
privateKey = nrsa.exportKey('pkcs1-private');
publicKey = nrsa.exportKey('pkcs1-public');
fs.writeFileSync('key.pem', privateKey);
fs.writeFileSync('pub.pem', publicKey);
