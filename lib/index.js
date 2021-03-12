'use strict';
require('dotenv').config();
const promise = require('bluebird');
const path = require('path');
const fs = require('fs');
const _ = require('lodash');
const crypt = require('./crypt');

const key = process.env.KEY;
let file;
module.exports.init = function (config, protectedcf = null) {
	file = path.resolve(config);
	let configuration = require(file);
	if (!('protection' in configuration)) {
		protect(configuration);
	}
};

const protect = function (_json) {
	let promises = [];
	if ('pk_config' in _json) {
		_.map(_json.sk_config, function (key) {
			let data = _.get(_json, key);
			promises.push(encrypt(key, data));
		});
	}

	promise.all(promises).then((response) => {
		const keyBy = _.keyBy(response, 'label');
		_.map(_json.sk_config, function (key) {
			let base64 = keyBy[key].base64;
			_.set(_json, key, base64);
		});

		writeJson(_json);
	});
};

const writeJson = function (json) {
	json.protection = true;
	let content = {};
	if (path.extname(file) === '.js') {
		content = `module.exports=${JSON.stringify(json, null, 4)}`;
	} else {
		content = JSON.stringify(json, null, 4);
	}
	fs.writeFileSync(file, content);
};

module.exports.encrypt = function (label, text) {
	const data = crypt.encrypt(text, key);
	if (data) {
		console.log('base64 encrypted string: ' + data);
		return { label, base64: data };
	} else {
		return null;
	}
};

module.exports.decrypt = async function (base64EncryptedString, label) {
	const decrypted = crypt.decrypt(base64EncryptedString, key);
	if (decrypted) {
		return { label, decrypted };
	}
};
