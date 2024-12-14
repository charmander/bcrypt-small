import {Buffer} from 'node:buffer';
import * as crypto from 'node:crypto';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const binding = require('./build/Release/bcrypt.node');

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

export const hash = (password, logRounds) => {
	if (typeof password !== 'string') {
		throw new TypeError('Password must be a string');
	}

	if (!Number.isSafeInteger(logRounds)) {
		throw new TypeError('logRounds must be an integer');
	}

	if (logRounds < 4 || logRounds > 31) {
		throw new RangeError('logRounds must be at least 4 and at most 31');
	}

	if (Buffer.byteLength(password, 'utf8') > 72) {
		return Promise.reject(new RangeError(`Password cannot be longer than 72 UTF-8 bytes`));
	}

	if (password.includes('\0')) {
		return Promise.reject(new Error('Password cannot contain null characters'));
	}

	const saltBytes = crypto.randomBytes(16);
	const salt = BCRYPT_PREFIX + padLogRounds(logRounds) + '$' + bcryptBase64(saltBytes);

	return new Promise((resolve, reject) => {
		binding(password, salt, (error, hash) => {
			if (error) {
				reject(error);
			} else {
				resolve(hash);
			}
		});
	});
};

export const compare = (password, expectedHash) => {
	if (typeof password !== 'string') {
		throw new TypeError('Password must be a string');
	}

	if (typeof expectedHash !== 'string') {
		throw new TypeError('Hash must be a string');
	}

	if (Buffer.byteLength(password, 'utf8') > 72) {
		return Promise.reject(new RangeError(`Password cannot be longer than 72 UTF-8 bytes`));
	}

	if (password.includes('\0')) {
		return Promise.reject(new Error('Password cannot contain null characters'));
	}

	return new Promise((resolve, reject) => {
		binding(password, expectedHash, (error, hash) => {
			if (error) {
				reject(error);
			} else {
				resolve(expectedHash === hash);
			}
		});
	});
};

export const getRounds = hash => {
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
