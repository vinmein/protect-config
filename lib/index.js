'use strict'
require('dotenv').config()
const promise = require('bluebird')
const path = require('path')
const fs = require('fs')
const AWS = require('aws-sdk');
const _ = require('lodash');
AWS.config.update({
    accessKeyId: process.env.AWS_KEY,
    secretAccessKey: process.env.AWS_SECRET,
    region: "ap-southeast-1"
});
const kms = new AWS.KMS();
const keyId = process.env.KEYID
let file
module.exports.init = function (config, protectedcf = null) {
    file = path.resolve(config)
    let configuration = require(file)
    if (!('protection' in configuration)) {
        protect(configuration)
    }
}

const protect = function (_json) {
    let promises = []
    if ('sk_config' in _json) {
        _.map(_json.sk_config, function (key) {
            let data = _.get(_json, key)
            promises.push(encrypt(key, data))
        })
    }

    promise.all(promises).then((response) => {
        const keyBy = _.keyBy(response, 'label')
        _.map(_json.sk_config, function (key) {
            let base64 = keyBy[key].base64
            _.set(_json, key, base64)
        })

        writeJson(_json)
    })
}

const writeJson = function (json) {
    json.protection = true
    let content = {}
    if (path.extname(file) === ".js") {
        content = `module.exports=${JSON.stringify(json, null, 4)}`
    } else {
        content = JSON.stringify(json, null, 4)
    }
    fs.writeFileSync(file, content)
}

module.exports.encrypt = async function (label, text) {

    const params = {
        KeyId: keyId, // your key alias or full ARN key
        Plaintext: text, // your super secret.
    };
    const data = await kms.encrypt(params).promise()

    if (data) {
        const base64EncryptedString = data.CiphertextBlob.toString('base64');
        console.log('base64 encrypted string: ' + base64EncryptedString);
        return { label, base64: base64EncryptedString };
    } else {
        return null
    }
}



module.exports.decrypt = async function (base64EncryptedString, label) {
    const decrypted = await kms.decrypt({
        CiphertextBlob: Buffer(base64EncryptedString, 'base64')
    }).promise()

    if (decrypted) {
        return { label, decrypted }
    }
}
