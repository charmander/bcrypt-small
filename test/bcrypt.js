/*
 * Test cases taken from or checked against https://github.com/pyca/bcrypt.
 */

'use strict';

var Bluebird = require('bluebird');
var tap = require('tap');

var bcrypt = require('../');
var hashAsync = Bluebird.promisify(bcrypt.hash);
var compareAsync = Bluebird.promisify(bcrypt.compare);

var FIXED_RANDOM_BYTES = Buffer.from([1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 128, 0, 16]);

function withFixedRandom(f) {
	var crypto = require('crypto');
	var _randomBytes = crypto.randomBytes;

	crypto.randomBytes = function randomBytes(n) {
		if (n !== FIXED_RANDOM_BYTES.length) {
			crypto.randomBytes = _randomBytes;
			tap.bailout('An unexpected number of random bytes was requested');
			return _randomBytes(n);
		}

		return FIXED_RANDOM_BYTES;
	};

	var result = f();

	crypto.randomBytes = _randomBytes;

	return result;
}

function repeat(s, n) {
	return new Array(n + 1).join(s);
}

tap.test('Valid hashes should compare correctly', function (t) {
	var correct = Bluebird.all([
		compareAsync('Kk4DQuMMfZL9o', '$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm'),
		compareAsync('9IeRXmnGxMYbs', '$2b$04$pQ7gRO7e6wx/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy'),
		compareAsync('xVQVbwa1S0M8r', '$2b$04$SQe9knOzepOVKoYXo9xTteNYr6MBwVz4tpriJVe3PNgYufGIsgKcW'),
		compareAsync('Zfgr26LWd22Za', '$2b$04$eH8zX.q5Q.j2hO1NkVYJQOM6KxntS/ow3.YzVmFrE4t//CoF4fvne'),
		compareAsync('Tg4daC27epFBE', '$2b$04$ahiTdwRXpUG2JLRcIznxc.s1.ydaPGD372bsGs8NqyYjLY1inG5n2'),
		compareAsync('xhQPMmwh5ALzW', '$2b$04$nQn78dV0hGHf5wUBe0zOFu8n07ZbWWOKoGasZKRspZxtt.vBRNMIy'),
		compareAsync('59je8h5Gj71tg', '$2b$04$cvXudZ5ugTg95W.rOjMITuM1jC0piCl3zF5cmGhzCibHZrNHkmckG'),
		compareAsync('wT4fHJa2N9WSW', '$2b$04$YYjtiq4Uh88yUsExO0RNTuEJ.tZlsONac16A8OcLHleWFjVawfGvO'),
		compareAsync('uSgFRnQdOgm4S', '$2b$04$WLTjgY/pZSyqX/fbMbJzf.qxCeTMQOzgL.CimRjMHtMxd/VGKojMu'),
		compareAsync('tEPtJZXur16Vg', '$2b$04$2moPs/x/wnCfeQ5pCheMcuSJQ/KYjOZG780UjA/SiR.KsYWNrC7SG'),
		compareAsync('vvho8C6nlVf9K', '$2b$04$HrEYC/AQ2HS77G78cQDZQ.r44WGcruKw03KHlnp71yVQEwpsi3xl2'),
		compareAsync('5auCCY9by0Ruf', '$2b$04$vVYgSTfB8KVbmhbZE/k3R.ux9A0lJUM4CZwCkHI9fifke2.rTF7MG'),
		compareAsync('GtTkR6qn2QOZW', '$2b$04$JfoNrR8.doieoI8..F.C1OQgwE3uTeuardy6lw0AjALUzOARoyf2m'),
		compareAsync('zKo8vdFSnjX0f', '$2b$04$HP3I0PUs7KBEzMBNFw7o3O7f/uxaZU7aaDot1quHMgB2yrwBXsgyy'),
		compareAsync('I9VfYlacJiwiK', '$2b$04$xnFVhJsTzsFBTeP3PpgbMeMREb6rdKV9faW54Sx.yg9plf4jY8qT6'),
		compareAsync('VFPO7YXnHQbQO', '$2b$04$WQp9.igoLqVr6Qk70mz6xuRxE0RttVXXdukpR9N54x17ecad34ZF6'),
		compareAsync('VDx5BdxfxstYk', '$2b$04$xgZtlonpAHSU/njOCdKztOPuPFzCNVpB4LGicO4/OGgHv.uKHkwsS'),
		compareAsync('dEe6XfVGrrfSH', '$2b$04$2Siw3Nv3Q/gTOIPetAyPr.GNj3aO0lb1E5E9UumYGKjP9BYqlNWJe'),
		compareAsync('cTT0EAFdwJiLn', '$2b$04$7/Qj7Kd8BcSahPO4khB8me4ssDJCW3r4OGYqPF87jxtrSyPj5cS5m'),
		compareAsync('J8eHUDuxBB520', '$2b$04$VvlCUKbTMjaxaYJ.k5juoecpG/7IzcH1AkmqKi.lIZMVIOLClWAk.'),
		compareAsync('bad',           '$2b$04$oahK9cRD70runDCHDv0guePBLj1bXnkhJsLE8RsxbIj/KTrjGTaTC'),
		compareAsync(repeat('x', 72), '$2b$04$reNliC3NXTL4gRd0vpEDNuSIvBhc.ELFskR71Dp5m15rUZAYSiU2y'),
		compareAsync(repeat('☃', 24), '$2b$04$eOi5Nnq3eFy9AyqQAKrFjOnaMtfXlcgH8qoRkCZ8zLACP.C9FuNEu'),
	]).then(function (results) {
		t.ok(results.every(Boolean));
	});

	var incorrect = Bluebird.all([
		compareAsync('Kk4DQuMMfZL9o',        '$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEq'),
		compareAsync('9IeRXmnGxMYbs',        '$2b$04$pQ7gRO7e6Ax/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy'),
		compareAsync('xVQVbwa1S0M8s',        '$2b$04$SQe9knOzepOVKoYXo9xTteNYr6MBwVz4tpriJVe3PNgYufGIsgKcW'),
		compareAsync('Rfgr26LWd22Za',        '$2b$04$eH8zX.q5Q.j2hO1NkVYJQOM6KxntS/ow3.YzVmFrE4t//CoF4fvne'),
		compareAsync('Tg4daC27epFB',         '$2b$04$ahiTdwRXpUG2JLRcIznxc.s1.ydaPGD372bsGs8NqyYjLY1inG5n2'),
		compareAsync('',                     '$2b$04$nQn78dV0hGHf5wUBe0zOFu8n07ZbWWOKoGasZKRspZxtt.vBRNMIy'),
		compareAsync('<I1NwC*N/T$n{',        '$2b$04$cvXudZ5ugTg95W.rOjMITuM1jC0piCl3zF5cmGhzCibHZrNHkmckG'),
		compareAsync(']vbE\'-I!S)69PI"Wmkv', '$2b$04$YYjtiq4Uh88yUsExO0RNTuEJ.tZlsONac16A8OcLHleWFjVawfGvO'),
		compareAsync(':Z@Q3m6/"{=UN=~/',     '$2b$04$WLTjgY/pZSyqX/fbMbJzf.qxCeTMQOzgL.CimRjMHtMxd/VGKojMu'),
		compareAsync('5r;yO=T}m[cP/5I',      '$2b$04$2moPs/x/wnCfeQ5pCheMcuSJQ/KYjOZG780UjA/SiR.KsYWNrC7SG'),
		compareAsync('kr$e+Pl/^H7@-5',       '$2b$04$HrEYC/AQ2HS77G78cQDZQ.r44WGcruKw03KHlnp71yVQEwpsi3xl2'),
		compareAsync('*b:,Ok^/SL=F<([^d',    '$2b$04$vVYgSTfB8KVbmhbZE/k3R.ux9A0lJUM4CZwCkHI9fifke2.rTF7MG'),
		compareAsync('V,u=OesoUHOvx{sAU',    '$2b$04$JfoNrR8.doieoI8..F.C1OQgwE3uTeuardy6lw0AjALUzOARoyf2m'),
		compareAsync('fgxppn10p,JQ',         '$2b$04$HP3I0PUs7KBEzMBNFw7o3O7f/uxaZU7aaDot1quHMgB2yrwBXsgyy'),
		compareAsync("Ap'^$Eb3RKwYOC<;GQY",  '$2b$04$xnFVhJsTzsFBTeP3PpgbMeMREb6rdKV9faW54Sx.yg9plf4jY8qT6'),
		compareAsync('$$QS->xei*',           '$2b$04$WQp9.igoLqVr6Qk70mz6xuRxE0RttVXXdukpR9N54x17ecad34ZF6'),
		compareAsync('2}6k0_Yy4<.!',         '$2b$04$xgZtlonpAHSU/njOCdKztOPuPFzCNVpB4LGicO4/OGgHv.uKHkwsS'),
		compareAsync(',m5zBk<K"5z',          '$2b$04$2Siw3Nv3Q/gTOIPetAyPr.GNj3aO0lb1E5E9UumYGKjP9BYqlNWJe'),
		compareAsync('m_c<NXBg3OMXmzx[',     '$2b$04$7/Qj7Kd8BcSahPO4khB8me4ssDJCW3r4OGYqPF87jxtrSyPj5cS5m'),
		compareAsync('C?{/@`RkZlQ4)01ga9~',  '$2b$04$VvlCUKbTMjaxaYJ.k5juoecpG/7IzcH1AkmqKi.lIZMVIOLClWAk.'),
	]).then(function (results) {
		t.ok(!results.some(Boolean));
	});

	return Bluebird.all([correct, incorrect]);
});

tap.test('Invalid hashes should produce comparison errors', function (t) {
	function compareFails(password, hash) {
		return compareAsync(password, hash).then(
			function () {
				return false;
			},
			function () {
				return true;
			}
		);
	}

	return Bluebird.all([
		compareFails('password', '$2z$04$cVWp4XaNU8a4v1uMRum2SO'),
		compareFails('password', '$2b$04$cVWp4XaNU8a4v1uMRum2S'),
		compareFails('password', ''),
		compareFails('password', ':'),
	]).then(function (results) {
		t.ok(results.every(Boolean));
	});
});

tap.test('Invalid passwords should produce hashing errors', function (t) {
	function hashFails(password) {
		return hashAsync(password, 10).then(
			function () {
				return false;
			},
			function () {
				return true;
			}
		);
	}

	return Bluebird.all([
		hashFails('bad\0'),
		hashFails(repeat('x', 73)),
		hashFails(repeat('☃', 24) + 'x'),
	]).then(function (results) {
		t.ok(results.every(Boolean));
	});
});

tap.test('Invalid passwords should produce comparison errors', function (t) {
	function compareFails(password, hash) {
		return compareAsync(password, hash).then(
			function () {
				return false;
			},
			function () {
				return true;
			}
		);
	}

	return Bluebird.all([
		compareFails('bad\0', '$2b$04$oahK9cRD70runDCHDv0guePBLj1bXnkhJsLE8RsxbIj/KTrjGTaTC'),
		compareFails(repeat('x', 73), '$2b$04$reNliC3NXTL4gRd0vpEDNuSIvBhc.ELFskR71Dp5m15rUZAYSiU2y'),
		compareFails(repeat('☃', 24) + 'x', '$2b$04$eOi5Nnq3eFy9AyqQAKrFjOnaMtfXlcgH8qoRkCZ8zLACP.C9FuNEu'),
	]).then(function (results) {
		t.ok(results.every(Boolean));
	});
});

tap.test('Valid passwords should hash correctly', function (t) {
	return Bluebird.all(
		withFixedRandom(function () {
			return [
				hashAsync('good', 10),
				hashAsync(repeat('x', 72), 10),
				hashAsync(repeat('☃', 24), 10),
			];
		})
	).then(function (results) {
		t.strictSame(results, [
			'$2b$10$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW',
			'$2b$10$.OCA.uSGBPSgLzkO4W..C.spnIjx92N76s/MBKwhVtjc4mJqFs1wq',
			'$2b$10$.OCA.uSGBPSgLzkO4W..C.ZoNOX6xIlYCjIQ7jr5gCMdszV5RPN7q',
		]);
	});
});

tap.test('Rounds should be extracted correctly', function (t) {
	t.equal(bcrypt.getRounds('$2b$10$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW'), 10);
	t.equal(bcrypt.getRounds('$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm'), 4);
	t.throws(function () {
		bcrypt.getRounds('$2z$10$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW');
	});
	t.end();
});
