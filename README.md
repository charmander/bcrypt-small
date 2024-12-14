# bcrypt-small

bcrypt-small provides functions to asynchronously create and verify password
hashes.

Passwords are encoded as UTF-8, cannot contain null bytes, and must be
no longer than 72 bytes; an error is produced if these conditions are not met.


## Example

```javascript
import * as bcrypt from 'bcrypt-small';

const hash = await bcrypt.hash('password', 12);

await bcrypt.compare('password', hash)
// true

await bcrypt.compare('not password', hash)
// false

bcrypt.getRounds(hash)
// 12
```


## API

### bcrypt.hash(password, logRounds)

Hashes a password using 2\*\*`logRounds` rounds, returning a promise. The hash
is a 60-character string. `logRounds` should be at least 4 and at most 31. Aim
for 0.1 seconds per hash or more.

### bcrypt.compare(password, expectedHash)

Compares a password to a hash, returning a promise that resolves to `true` if
the password matches the hash and `false` if it does not.

### bcrypt.getRounds(hash)

Returns the number of rounds used to produce the given hash.
