'use strict';

const binding = require('./build/Release/bcrypt');
const crypto = require('crypto');

const BCRYPT_PREFIX = '$2b$';
const BCRYPT_BASE64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BCRYPT_ROUNDS = /^\$2[ab]\$(\d{2})\$/;

const bcryptBase64 = bytes => {
	let i;
	const l = bytes.length;
	let result = '';

	for (i = 0; i + 2 < l; i += 3) {
		const b0 = bytes[i];
		const b1 = bytes[i + 1];
		const b2 = bytes[i + 2];

		result +=
			BCRYPT_BASE64.charAt(b0 >> 2) +
			BCRYPT_BASE64.charAt(((b0 & 0x03) << 4) | (b1 >> 4)) +
			BCRYPT_BASE64.charAt(((b1 & 0x0f) << 2) | (b2 >> 6)) +
			BCRYPT_BASE64.charAt(b2 & 0x3f);
	}

	/* istanbul ignore next: unreachable */
	if (i + 1 !== l) {
		throw new Error('Unexpected salt length');
	}

	{
		const b0 = bytes[i];

		result +=
			BCRYPT_BASE64.charAt(b0 >> 2) +
			BCRYPT_BASE64.charAt((b0 & 0x03) << 4);
	}

	return result;
};

const padLogRounds = logRounds =>
	logRounds < 10 ? '0' + logRounds : '' + logRounds;

const hash = (password, logRounds, callback) => {
	if (typeof password !== 'string') {
		throw new TypeError('Password must be a string');
	}

	if (!Number.isSafeInteger(logRounds)) {
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

	if (password.includes('\0')) {
		process.nextTick(callback, new Error('Password cannot contain null characters'), undefined);
		return;
	}

	const saltBytes = crypto.randomBytes(16);
	const salt = BCRYPT_PREFIX + padLogRounds(logRounds) + '$' + bcryptBase64(saltBytes);

	binding.hashPasswordAsync(password, salt, callback);
};

const compare = (password, expectedHash, callback) => {
	if (typeof password !== 'string') {
		throw new TypeError('Password must be a string');
	}

	if (typeof expectedHash !== 'string') {
		throw new TypeError('Hash must be a string');
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

	binding.hashPasswordAsync(password, expectedHash, (error, hash) => {
		if (error) {
			callback(error, undefined);
		} else {
			callback(null, expectedHash === hash);
		}
	});
};

const getRounds = hash => {
	if (typeof hash !== 'string') {
		throw new TypeError('Hash must be a string');
	}

	const match = BCRYPT_ROUNDS.exec(hash);

	if (match) {
		return match[1] | 0;
	} else {
		throw new Error('Invalid hash');
	}
};

module.exports = {
	hash,
	compare,
	getRounds,
};
