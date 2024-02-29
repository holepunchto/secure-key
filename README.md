# secure-key

Password protected ed25519 key pairs.

## Usage

```js
await SecureKey.generate('/path/to/keyfile')

// interactive prompt for password
```

```js
const keyPair = await SecureKey.open('/path/to/keyfile')

// interactive prompt for password

// key pair is locked initially  
keyPair.unlock()

// use key pair  
const signature = crypto.sign(message, keyPair)

// lock key pair in between usage
keyPair.lock()

// ... do some more

// clear key pair finally
keyPair.clear()
```

## API

#### `SecureKey.secretKeyLength`

Byte length of secret key

#### `SecureKey.publicKeyLength`

Byte length of public key

#### `await SecureKey.generate(path, opts)`

Generate a new key pair and store to `path`.

Public key will be written to `path.public`

`opts` can be passed:
- `password`: specify password for non-interactive mode

#### `const keyPair = await SecureKey.open(path, opts)`

Open a key pair stored at `path`.

`opts` can be passed:
- `password`: specify password for non-interactive mode
- `protected`: `false` by default. If set to `true`, secret key will be written to [protected memory](https://sodium-friends.github.io/docs/docs/memoryprotection)

#### `keyPair.unlock()`

Unlock the key pair.

Throws an error if secret key is not in secure memory.

#### `keyPair.lock()`

Lock the key pair.

Any attmept to access keyPair.secretKey will trigger a segfault.

Throws an error if secret key is not in secure memory.

#### `keyPair.clear()`

Clear the secret key from memory.

#### `keyPair.secretKey`

The secret key.

#### `keyPair.publicKey`

The public key.

#### `keyPair.locked`

Boolean indicating if the key pair is locked.

## License

Apache-2.0
