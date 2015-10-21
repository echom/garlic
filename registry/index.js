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
		hashKey = function(key) {
			var salt = crypto.randomBytes(4).toString('hex'),
			return salt + '$' + hashKeyWithSalt(salt);
		},
		hashKeyWithSalt = function(key, salt) {
			return hash = crypto.createHmac('sha-1', salt).update(key).digest(hex);
		},
		makeUserResponse = function(pubkey, server) {
			return Buffer.concat(
				rows[0].pubkey,
				Buffer.byteLength(rows[0].server, 'utf-8'),
				new Buffer(rows[0].server, 'utf-8')
			)
		},
		fail: function(res, code) {
			console.log('garlic-registry: FAIL', code);

			res.status(code);
			switch(code) {
				case 400: res.end('Bad Request'); break;
				case 403: res.end('Forbidden'); break;
				case 404: res.end('Not Found'); break;
				case 405: res.end('Method Not Allowed'); break;
				case 500: res.end('Internal Server Error'); break;
				default: res.end('Unknown Error'); break;
			}
		},
		respond: function(res, resKey, resIV, data) {
			var aes = crypto.createCipheriv('aes-256-cbc', resKey, resIV);
			aes.pipe(res);
			aes.end(data);
		},
		getUser = function(user, res, resKey, resIV) {
			console.log('garlic-registry: request info', user);
			db.query('SELECT * FROM users WHERE id = ?', [user], function(err, rows) {
				console.log('garlic-registry: query complete', err);

				var aes;
				if(err) { fail(res, 500); }
				else if(rows.length == 0) { fail(res, 404); }
				else {
					respond(res, resKey, resIV, makeUserResponse(rows[0].pubkey, rows[0].server));
				}
			});
		},
		registerUser = function(data, res, callback) {
			console.log('garlic-registry: registering user', user);
			var updateKey = crypto.randomBytes(32),
				user = data.slice(0, 32),
				pubkey = data.slice(32, 288),
				serverLength = data.slice(288, 289),
				server = data.slice(289, 289 + serverLength),
				updateKeyHash = hashKey(updateKey);

			db.query('SELECT id FROM users WHERE id = ?', [user], function(err, rows) {
				if(err) { fail(res, 500); }
				else if(rows.length > 0) { fail(res, 403); }
				else {
					db.query(
						'INSERT INTO users (id, pubkey, server, updatekey) VALUES (?, ?, ?, ?)',
						[id, pubkey, server, updateKeyHash],
						function(err, result) {
							if(result.affectedRows == 1) { callback(updateKey); }
							else if(result.affectedRows == 0) { fail(res, 403); }
							else if(err) { fail(res, 500); }
						}
					);
				}
			});
		},
		updateUser = function(data, res, callback) {
			var updateKey = data.slice(32),
				user = data.slice(32, 64),
				pubkey = data.slice(64, 320),
				serverLength = data.slice[320],
				server = data.slice(321, 321 + serverLength),
				updateKeyHash;

			db.query('SELECT updatekey FROM users WHERE id = ?', [user], function(err, rows) {
				if(err) { fail(res, 500); }
				else if(rows.length = 0) { fail(res, 403); }
				else {
					var updateKeyHash = rows[0].updatekey.split('$'),
						salt = updateKeyHash[0],
						hash = updateKeyHash[1];
					if(hashKeyWithSalt(updateKey, salt) == hash) {

					} else {
						fail(res, 403);
					}
				}
			});
		},
		deleteUser = function(data, res, callback) {},
		modifyUser = function(user, req, reqKey, reqIV, res, resKey, resIV) {
			console.log('garlic-registry: request modification');

			var aes = crypto.createDecipheriv('aes-256-cbc', reqKey, reqIV),
				data = [],
				modification,
				onUserModified = function(data) { respond(res, resKey, resIV, data); };

			aes.on('data', function(chunk) { data.push(chunk); }):
			aes.on('end', function() {
				data = Buffer.concat(data);
				modification = data[0];
				data = data.slice(1);
				switch(modification) {
					case MOD_REGISTER: registerUser(data, res, onUserModified); break;
					case MOD_UPDATE: updateUser(data, res, onUserModified); break;
					case MOD_DELETE: deleteUser(data, res, onUserModified); break;
					default: res.status(400).end('Bad Request'); break;
				}
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
