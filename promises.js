'use strict';

const {hash, compare, getRounds} = require('./');

const hashAsync = (password, logRounds) => {
	let resolve;
	let reject;

	const promise = new Promise((resolve_, reject_) => {
		resolve = resolve_;
		reject = reject_;
	});

	hash(password, logRounds, (error, result) => {
		if (error) {
			reject(error);
		} else {
			resolve(result);
		}
	});

	return promise;
};

const compareAsync = (password, expectedHash) => {
	let resolve;
	let reject;

	const promise = new Promise((resolve_, reject_) => {
		resolve = resolve_;
		reject = reject_;
	});

	compare(password, expectedHash, (error, result) => {
		if (error) {
			reject(error);
		} else {
			resolve(result);
		}
	});

	return promise;
};

module.exports = {
	hash: hashAsync,
	compare: compareAsync,
	getRounds,
};
