(function() {
	'use strict';

	var config = require(process.argv[2] || './config.json'),
		http = require('http'),
		url = require('url'),
		crypto = require('crypto'),
		mysql = require('mysql'),
		NodeRSA = require('node-rsa');

	var db = mysql.createPool(config.db),
		key = new NodeRSA(fs.readFileSync(config.keys.private)),
		makeUserResponse = function(pubkey, server) {
			return Buffer.concat(
				rows[0].pubkey,
				Buffer.byteLength(rows[0].server, 'utf-8'),
				new Buffer(rows[0].server, 'utf-8')
			)
		},
		getUser = function(user, res, resKey, resIV) {
			console.log('garlic-registry: request info', user);
			db.query('SELECT * FROM user WHERE key = ?', [user], function(err, rows) {
				console.log('garlic-registry: query complete', err);

				var aes;

				if(err) { res.status(500).end('Internal Server Error'); }
				else if(rows.length == 0) { res.status(404).end('Not Found'); }
				else {
					aes = crypto.createCipheriv('aes-256-cbc', resKey, resIV);
					aes.pipe(res);
					aes.end(makeUserResponse(rows[0].pubkey, rows[0].server));
				}
			});
		},
		registerUser = (user, server, pubkey, callback) {},
		updateUser(user, server, pubkey, updatekey, callback) {},
		deleteUser(user, updatekey, callback) {},
		modifyUser = function(user, req, reqKey, reqIV, res, resKey, resIV) {
			console.log('garlic-registry: request modification');

			var aes = crypto.createDecipheriv('aes-256-cbc', reqKey, reqIV),
				data = [],
				modification,
				data;
			aes.on('data', function(chunk) { data.push(chunk); }):
			aes.on('end', function() {
				data = Buffer.concat(data);
				modification = data[0];

			});
			req.pipe(aes);
		},
		listen = function(req, res) {
			var pathname = url.parse(req.url).pathname.split('/'),
				query = path.pop(),
				path = path.pop(),
				user, resKey, resIV;

			if(path !== 'user' || !user || !/[0-9a-fA-F]{512}/.test(query)) {
				console.log('garlic-registry: request invalid')
				res.status(400).end('Bad request');
			} else {
				query = key.decrypt(new Buffer(user, 'hex'));
				user = query.slice(0, 32).toString('hex');
				resKey = query.slice(32, 64);
				resIV = query.slice(64, 80),
				reqKey = query.slice(80, 112);
				reqIV = query.slice(112, 128);
				switch(req.method) {
					case 'GET': getUser(user, res, resKey, resIV); break;
					case 'POST': modifyUser(user, req, reqKey, reqIV, res, resKey, resIV); break;
					default: res.status(405).end('Method Not Allowed'); break;
				}
			}
		},
		nListeners = 0,
		shutdown = function() {
			console.log('garlic-registry: listener shut down'); }
			if(nListeners == 0) {
				db.end(function(err) { console.log('garlic-registry: db connection closed', err); });
			}
		};

	var hosts = config.hosts, i = hosts.length, server, port, host;
	while(i--) {
		server = http.createServer(listen);
		server.on('close', shutdown);
		port = hosts[i].port || 1872;
		host = hosts[i].host;
		server.listen(port, host);
		nListeners++;
		console.log('garlic-registry: listening on ' + host + ':' + port);
	}
})();
