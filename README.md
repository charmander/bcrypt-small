# bcrypt-small

[![Build status][ci-image]][ci]

bcrypt-small provides functions to asynchronously create and verify password
hashes.

Passwords are encoded as UTF-8, cannot contain null bytes, and must be
no longer than 72 bytes; an error is produced if these conditions are not met.


## Example

```javascript
var bcrypt = require('bcrypt-small');

bcrypt.hash('password', 10, function (error, hash) {
	if (error) {
		console.error(error);
		return;
	}

	bcrypt.compare('password', hash, function (error, result) {
		console.log(result); // true
	});

	bcrypt.compare('not password', hash, function (error, result) {
		console.log(result); // false
	});
});
```


## API

### bcrypt.hash(password, logRounds, callback)

Hashes a password using 2\*\*`logRounds` rounds. The callback receives two
arguments: `(error, hash)`, where `hash` is a 60-character string. `logRounds`
should be at least 4 and at most 31. Aim for 0.1 seconds per hash or more.

### bcrypt.compare(password, expectedHash, callback)

Compares a password to a hash. The callback receives two arguments:
`(error, result)`, where `result` is `true` if the password matches the hash and
`false` if it does not.

### bcrypt.getRounds(hash)

Returns the number of rounds used to produce the given hash.


  [ci]: https://travis-ci.org/charmander/bcrypt-small
  [ci-image]: https://api.travis-ci.org/charmander/bcrypt-small.svg
