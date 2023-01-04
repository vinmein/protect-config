const _crypto = require('crypto');

// encrypt/decrypt functions
module.exports = {
	/**
	 * Encrypts text by given key
	 * @param String text to encrypt
	 * @param Buffer masterkey
	 * @returns String encrypted text, base64 encoded
	 */
	encrypt: function (
		text,
		masterkey,
		type = 'DYNAMIC',
		options = { iv: null, salt: null },
	) {
		let iv, salt;
		if (type == 'DYNAMIC') {
			// random initialization vector
			iv = _crypto.randomBytes(16);
			// random salt
			salt = _crypto.randomBytes(64);
		} else {
			// random initialization vector
			iv = options.iv;
			// random salt
			salt = options.salt;
		}

		// derive encryption key: 32 byte key length
		// in assumption the masterkey is a cryptographic and NOT a password there is no need for
		// a large number of iterations. It may can replaced by HKDF
		// the value of 2145 is randomly chosen!
		const key = _crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');

		// AES 256 GCM Mode
		const cipher = _crypto.createCipheriv('aes-256-gcm', key, iv);

		// encrypt the given text
		const encrypted = Buffer.concat([
			cipher.update(text, 'utf8'),
			cipher.final(),
		]);

		// extract the auth tag
		const tag = cipher.getAuthTag();

		// generate output
		return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
	},

	/**
	 * Decrypts text by given key
	 * @param String base64 encoded input data
	 * @param Buffer masterkey
	 * @returns String decrypted (original) text
	 */
	decrypt: function (encdata, masterkey) {
		// base64 decoding
		try {
			const bData = Buffer.from(encdata, 'base64');

			// convert data to buffers

			const salt = bData.subarray(0, 64);
			const iv = bData.subarray(64, 80);
			const tag = bData.subarray(80, 96);
			const text = bData.subarray(96);

			// derive key using; 32 byte key length
			const key = _crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');

			// AES 256 GCM Mode
			const decipher = _crypto.createDecipheriv('aes-256-gcm', key, iv);
			decipher.setAuthTag(tag);

			// encrypt the given text
			const decrypted =
				decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');

			return decrypted;
		} catch (e) {
			console.log(e);
			throw e;
		}
	},

	encryptV2: function (data, enckey, enciv) {
		const key = Buffer.from(enckey, 'base64'); // //"xNRxA48aNYd33PXaODSutRNFyCu4cAe/InKT/Rx+bw0=",
		const iv = Buffer.from(enciv, 'base64'); //"81dFxOpX7BPG1UpZQPcS6w==",
		const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
		const encryptedData =
			cipher.update(data, 'utf8', 'base64') + cipher.final('base64');
		return encryptedData;
	},
	decryptV2: function (encdata, enckey, enciv) {
		const key = Buffer.from(enckey, 'base64'); // //"xNRxA48aNYd33PXaODSutRNFyCu4cAe/InKT/Rx+bw0=",
		const iv = Buffer.from(enciv, 'base64');
		const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
		const decripted =
			decipher.update(encdata, 'base64', 'utf8') + decipher.final('utf8');
		return decripted;
	},
};
