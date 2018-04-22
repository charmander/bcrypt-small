'use strict';

var binding = require('./build/Release/bcrypt');
var crypto = require('crypto');

var BCRYPT_PREFIX = '$2b$';
var BCRYPT_BASE64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
var BCRYPT_ROUNDS = /^\$2[ab]\$(\d{2})\$/;

function isInteger(value) {
	return value === (value | 0);
}

function bcryptBase64(bytes) {
	var i;
	var l = bytes.length;
	var result = '';
	var b0;
	var b1;
	var b2;

	for (i = 0; i + 2 < l; i += 3) {
		b0 = bytes[i];
		b1 = bytes[i + 1];
		b2 = bytes[i + 2];

		result +=
			BCRYPT_BASE64.charAt(b0 >> 2) +
			BCRYPT_BASE64.charAt(((b0 & 0x03) << 4) | (b1 >> 4)) +
			BCRYPT_BASE64.charAt(((b1 & 0x0f) << 2) | (b2 >> 6)) +
			BCRYPT_BASE64.charAt(b2 & 0x3f);
	}

	if (i + 1 === l) {
		b0 = bytes[i];

		result +=
			BCRYPT_BASE64.charAt(b0 >> 2) +
			BCRYPT_BASE64.charAt((b0 & 0x03) << 4);
	} else if (i + 2 === l) {
		b0 = bytes[i];
		b1 = bytes[i + 1];

		result +=
			BCRYPT_BASE64.charAt(b0 >> 2) +
			BCRYPT_BASE64.charAt(((b0 & 0x03) << 4) | (b1 >> 4)) +
			BCRYPT_BASE64.charAt((b1 & 0x0f) << 2);
	}

	return result;
}

function padLogRounds(logRounds) {
	return logRounds < 10 ? '0' + logRounds : '' + logRounds;
}

function hash(password, logRounds, callback) {
	if (typeof password !== 'string') {
		throw new TypeError('Password must be a string');
	}

	if (!isInteger(logRounds)) {
		throw new TypeError('logRounds must be an integer');
	}

	if (logRounds < 4 || logRounds > 31) {
		throw new RangeError('logRounds must be at least 4 and at most 31');
	}

	if (typeof callback !== 'function') {
		throw new TypeError('Callback must be a function');
	}

	if (Buffer.byteLength(password, 'utf8') > 72) {
		process.nextTick(callback, new RangeError('Password cannot be longer than 72 UTF-8 bytes'), undefined);
		return;
	}

	if (password.indexOf('\0') !== -1) {
		process.nextTick(callback, new Error('Password cannot contain null characters'), undefined);
		return;
	}

	var saltBytes = crypto.randomBytes(16);
	var salt = BCRYPT_PREFIX + padLogRounds(logRounds) + '$' + bcryptBase64(saltBytes);

	binding.hashPasswordAsync(password, salt, callback);
}

function compare(password, expectedHash, callback) {
	if (typeof password !== 'string') {
		throw new TypeError('Password must be a string');
	}

	if (typeof expectedHash !== 'string') {
		throw new TypeError('Hash must be a string');
	}

	if (Buffer.byteLength(password, 'utf8') > 72) {
		process.nextTick(callback, new RangeError('Password cannot be longer than 72 UTF-8 bytes'), undefined);
		return;
	}

	if (password.indexOf('\0') !== -1) {
		process.nextTick(callback, new Error('Password cannot contain null characters'), undefined);
		return;
	}

	binding.hashPasswordAsync(password, expectedHash, function (error, hash) {
		if (error) {
			callback(error, undefined);
		} else {
			callback(null, expectedHash === hash);
		}
	});
}

function getRounds(hash) {
	if (typeof hash !== 'string') {
		throw new TypeError('Hash must be a string');
	}

	var match = BCRYPT_ROUNDS.exec(hash);

	if (match) {
		return match[1] | 0;
	} else {
		throw new Error('Invalid hash');
	}
}

exports.hash = hash;
exports.compare = compare;
exports.getRounds = getRounds;
