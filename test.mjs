/*
 * Test cases taken from or checked against https://github.com/pyca/bcrypt.
 */

import {strict as assert} from 'node:assert';
import {test} from 'node:test';

import * as bcrypt from 'bcrypt-small';

const FIXED_RANDOM_BYTES = new Uint8Array([1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 128, 0, 16]);

const rejects = promise =>
	promise.then(
		() => false,
		() => true
	);

test('Valid hashes compare correctly', () => {
	const correct = Promise.all([
		bcrypt.compare('Kk4DQuMMfZL9o', '$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm'),
		bcrypt.compare('9IeRXmnGxMYbs', '$2b$04$pQ7gRO7e6wx/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy'),
		bcrypt.compare('xVQVbwa1S0M8r', '$2b$04$SQe9knOzepOVKoYXo9xTteNYr6MBwVz4tpriJVe3PNgYufGIsgKcW'),
		bcrypt.compare('Zfgr26LWd22Za', '$2b$04$eH8zX.q5Q.j2hO1NkVYJQOM6KxntS/ow3.YzVmFrE4t//CoF4fvne'),
		bcrypt.compare('Tg4daC27epFBE', '$2b$04$ahiTdwRXpUG2JLRcIznxc.s1.ydaPGD372bsGs8NqyYjLY1inG5n2'),
		bcrypt.compare('xhQPMmwh5ALzW', '$2b$04$nQn78dV0hGHf5wUBe0zOFu8n07ZbWWOKoGasZKRspZxtt.vBRNMIy'),
		bcrypt.compare('59je8h5Gj71tg', '$2b$04$cvXudZ5ugTg95W.rOjMITuM1jC0piCl3zF5cmGhzCibHZrNHkmckG'),
		bcrypt.compare('wT4fHJa2N9WSW', '$2b$04$YYjtiq4Uh88yUsExO0RNTuEJ.tZlsONac16A8OcLHleWFjVawfGvO'),
		bcrypt.compare('uSgFRnQdOgm4S', '$2b$04$WLTjgY/pZSyqX/fbMbJzf.qxCeTMQOzgL.CimRjMHtMxd/VGKojMu'),
		bcrypt.compare('tEPtJZXur16Vg', '$2b$04$2moPs/x/wnCfeQ5pCheMcuSJQ/KYjOZG780UjA/SiR.KsYWNrC7SG'),
		bcrypt.compare('vvho8C6nlVf9K', '$2b$04$HrEYC/AQ2HS77G78cQDZQ.r44WGcruKw03KHlnp71yVQEwpsi3xl2'),
		bcrypt.compare('5auCCY9by0Ruf', '$2b$04$vVYgSTfB8KVbmhbZE/k3R.ux9A0lJUM4CZwCkHI9fifke2.rTF7MG'),
		bcrypt.compare('GtTkR6qn2QOZW', '$2b$04$JfoNrR8.doieoI8..F.C1OQgwE3uTeuardy6lw0AjALUzOARoyf2m'),
		bcrypt.compare('zKo8vdFSnjX0f', '$2b$04$HP3I0PUs7KBEzMBNFw7o3O7f/uxaZU7aaDot1quHMgB2yrwBXsgyy'),
		bcrypt.compare('I9VfYlacJiwiK', '$2b$04$xnFVhJsTzsFBTeP3PpgbMeMREb6rdKV9faW54Sx.yg9plf4jY8qT6'),
		bcrypt.compare('VFPO7YXnHQbQO', '$2b$04$WQp9.igoLqVr6Qk70mz6xuRxE0RttVXXdukpR9N54x17ecad34ZF6'),
		bcrypt.compare('VDx5BdxfxstYk', '$2b$04$xgZtlonpAHSU/njOCdKztOPuPFzCNVpB4LGicO4/OGgHv.uKHkwsS'),
		bcrypt.compare('dEe6XfVGrrfSH', '$2b$04$2Siw3Nv3Q/gTOIPetAyPr.GNj3aO0lb1E5E9UumYGKjP9BYqlNWJe'),
		bcrypt.compare('cTT0EAFdwJiLn', '$2b$04$7/Qj7Kd8BcSahPO4khB8me4ssDJCW3r4OGYqPF87jxtrSyPj5cS5m'),
		bcrypt.compare('J8eHUDuxBB520', '$2b$04$VvlCUKbTMjaxaYJ.k5juoecpG/7IzcH1AkmqKi.lIZMVIOLClWAk.'),
		bcrypt.compare('bad',           '$2b$04$oahK9cRD70runDCHDv0guePBLj1bXnkhJsLE8RsxbIj/KTrjGTaTC'),
		bcrypt.compare('x'.repeat(72),  '$2b$04$reNliC3NXTL4gRd0vpEDNuSIvBhc.ELFskR71Dp5m15rUZAYSiU2y'),
		bcrypt.compare('☃'.repeat(24),  '$2b$04$eOi5Nnq3eFy9AyqQAKrFjOnaMtfXlcgH8qoRkCZ8zLACP.C9FuNEu'),
	]).then(results => {
		assert.ok(results.every(Boolean));
	});

	const incorrect = Promise.all([
		bcrypt.compare('Kk4DQuMMfZL9o',        '$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEq'),
		bcrypt.compare('9IeRXmnGxMYbs',        '$2b$04$pQ7gRO7e6Ax/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy'),
		bcrypt.compare('xVQVbwa1S0M8s',        '$2b$04$SQe9knOzepOVKoYXo9xTteNYr6MBwVz4tpriJVe3PNgYufGIsgKcW'),
		bcrypt.compare('Rfgr26LWd22Za',        '$2b$04$eH8zX.q5Q.j2hO1NkVYJQOM6KxntS/ow3.YzVmFrE4t//CoF4fvne'),
		bcrypt.compare('Tg4daC27epFB',         '$2b$04$ahiTdwRXpUG2JLRcIznxc.s1.ydaPGD372bsGs8NqyYjLY1inG5n2'),
		bcrypt.compare('',                     '$2b$04$nQn78dV0hGHf5wUBe0zOFu8n07ZbWWOKoGasZKRspZxtt.vBRNMIy'),
		bcrypt.compare('<I1NwC*N/T$n{',        '$2b$04$cvXudZ5ugTg95W.rOjMITuM1jC0piCl3zF5cmGhzCibHZrNHkmckG'),
		bcrypt.compare(']vbE\'-I!S)69PI"Wmkv', '$2b$04$YYjtiq4Uh88yUsExO0RNTuEJ.tZlsONac16A8OcLHleWFjVawfGvO'),
		bcrypt.compare(':Z@Q3m6/"{=UN=~/',     '$2b$04$WLTjgY/pZSyqX/fbMbJzf.qxCeTMQOzgL.CimRjMHtMxd/VGKojMu'),
		bcrypt.compare('5r;yO=T}m[cP/5I',      '$2b$04$2moPs/x/wnCfeQ5pCheMcuSJQ/KYjOZG780UjA/SiR.KsYWNrC7SG'),
		bcrypt.compare('kr$e+Pl/^H7@-5',       '$2b$04$HrEYC/AQ2HS77G78cQDZQ.r44WGcruKw03KHlnp71yVQEwpsi3xl2'),
		bcrypt.compare('*b:,Ok^/SL=F<([^d',    '$2b$04$vVYgSTfB8KVbmhbZE/k3R.ux9A0lJUM4CZwCkHI9fifke2.rTF7MG'),
		bcrypt.compare('V,u=OesoUHOvx{sAU',    '$2b$04$JfoNrR8.doieoI8..F.C1OQgwE3uTeuardy6lw0AjALUzOARoyf2m'),
		bcrypt.compare('fgxppn10p,JQ',         '$2b$04$HP3I0PUs7KBEzMBNFw7o3O7f/uxaZU7aaDot1quHMgB2yrwBXsgyy'),
		bcrypt.compare("Ap'^$Eb3RKwYOC<;GQY",  '$2b$04$xnFVhJsTzsFBTeP3PpgbMeMREb6rdKV9faW54Sx.yg9plf4jY8qT6'),
		bcrypt.compare('$$QS->xei*',           '$2b$04$WQp9.igoLqVr6Qk70mz6xuRxE0RttVXXdukpR9N54x17ecad34ZF6'),
		bcrypt.compare('2}6k0_Yy4<.!',         '$2b$04$xgZtlonpAHSU/njOCdKztOPuPFzCNVpB4LGicO4/OGgHv.uKHkwsS'),
		bcrypt.compare(',m5zBk<K"5z',          '$2b$04$2Siw3Nv3Q/gTOIPetAyPr.GNj3aO0lb1E5E9UumYGKjP9BYqlNWJe'),
		bcrypt.compare('m_c<NXBg3OMXmzx[',     '$2b$04$7/Qj7Kd8BcSahPO4khB8me4ssDJCW3r4OGYqPF87jxtrSyPj5cS5m'),
		bcrypt.compare('C?{/@`RkZlQ4)01ga9~',  '$2b$04$VvlCUKbTMjaxaYJ.k5juoecpG/7IzcH1AkmqKi.lIZMVIOLClWAk.'),
	]).then(results => {
		assert.ok(!results.some(Boolean));
	});

	return Promise.all([correct, incorrect]);
});

test('Invalid hashes produce comparison errors', () => {
	const compareFails = (password, hash) =>
		rejects(bcrypt.compare(password, hash));

	return Promise.all([
		compareFails('password', '$2z$04$cVWp4XaNU8a4v1uMRum2SO'),
		compareFails('password', '$2b$04$cVWp4XaNU8a4v1uMRum2S'),
		compareFails('password', ''),
		compareFails('password', ':'),
	]).then(results => {
		assert.ok(results.every(Boolean));
	});
});

test('Invalid passwords produce hashing errors', () => {
	const hashFails = password =>
		rejects(bcrypt.hash(password, 10));

	return Promise.all([
		hashFails('bad\0'),
		hashFails('x'.repeat(73)),
		hashFails('☃'.repeat(24) + 'x'),
	]).then(results => {
		assert.ok(results.every(Boolean));
	});
});

test('Invalid passwords produce comparison errors', () => {
	const compareFails = (password, hash) =>
		rejects(bcrypt.compare(password, hash));

	return Promise.all([
		compareFails('bad\0', '$2b$04$oahK9cRD70runDCHDv0guePBLj1bXnkhJsLE8RsxbIj/KTrjGTaTC'),
		compareFails('x'.repeat(73), '$2b$04$reNliC3NXTL4gRd0vpEDNuSIvBhc.ELFskR71Dp5m15rUZAYSiU2y'),
		compareFails('☃'.repeat(24) + 'x', '$2b$04$eOi5Nnq3eFy9AyqQAKrFjOnaMtfXlcgH8qoRkCZ8zLACP.C9FuNEu'),
	]).then(results => {
		assert.ok(results.every(Boolean));
	});
});

test('Valid passwords hash correctly', {skip: 'should not monkeypatch crypto'}, () =>
	Promise.all([
		bcrypt.hash('good', 10),
		bcrypt.hash('x'.repeat(72), 10),
		bcrypt.hash('☃'.repeat(24), 10),
	]).then(results => {
		assert.deepEqual(results, [
			'$2b$10$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW',
			'$2b$10$.OCA.uSGBPSgLzkO4W..C.spnIjx92N76s/MBKwhVtjc4mJqFs1wq',
			'$2b$10$.OCA.uSGBPSgLzkO4W..C.ZoNOX6xIlYCjIQ7jr5gCMdszV5RPN7q',
		]);
	})
);

test('Single-digit round counts hash correctly', async () => {
	const hash = await bcrypt.hash('good', 4);
	assert(hash.startsWith('$2b$04$'));
});

test('Incorrect parameter types result in errors at the time of the call', () => {
	assert.throws(() => {
		bcrypt.hash(null, 4);
	}, /^TypeError: Password must be a string$/);

	assert.throws(() => {
		bcrypt.hash('a', 4.5);
	}, /^TypeError: logRounds must be an integer$/);

	assert.throws(() => {
		bcrypt.hash('a', 3);
	}, /^RangeError: logRounds must be at least 4 and at most 31$/);

	assert.throws(() => {
		bcrypt.hash('a', 32);
	}, /^RangeError: logRounds must be at least 4 and at most 31$/);

	assert.throws(() => {
		bcrypt.compare(null, 'b');
	}, /^TypeError: Password must be a string$/);

	assert.throws(() => {
		bcrypt.compare('a', null);
	}, /^TypeError: Hash must be a string$/);

	assert.throws(() => {
		bcrypt.getRounds(null);
	}, /^TypeError: Hash must be a string$/);
});

test('Rounds are extracted correctly', () => {
	assert.equal(bcrypt.getRounds('$2b$10$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW'), 10);
	assert.equal(bcrypt.getRounds('$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm'), 4);
	assert.throws(() => {
		bcrypt.getRounds('$2z$10$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW');
	}, /^Error: Invalid hash$/);
	assert.throws(() => {
		bcrypt.getRounds('$2b$4$.OCA.uSGBPSgLzkO4W..C.bECUq4XHEv2q4q/Ez0YjVJ4zi9PN6UW');
	}, /^Error: Invalid hash$/);
});
