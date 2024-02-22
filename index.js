const path = require('path')
const fs = require('fs').promises
const sodium = require('sodium-native')
const securePrompt = require('secure-prompt')
const z32 = require('z32')
const c = require('compact-encoding')

const MIN_PASSWORD_LENGTH = 8
const USER_ONLY_RW = 0o600

const {
  labelledKey,
  keyDescriptor,
  encryptedKey
} = require('./lib/encoding')

module.exports = class SecureKey {
  constructor (secretKey) {
    this.secretKey = secretKey
    this.publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)

    this._locked = false
    this._cleared = false

    sodium.sodium_mprotect_readwrite(this.secretKey)
    sodium.crypto_sign_ed25519_sk_to_pk(this.publicKey, this.secretKey)
    sodium.sodium_mprotect_noaccess(this.secretKey)
  }

  static async open (keyFile, { password }) {
    try {
      await fs.stat(keyFile)
    } catch (e) {
      throw new Error('Error opening secret key file: ' + e.code)
    }

    const keyBuffer = z32.decode(await fs.readFile(keyFile, 'utf-8'))
    const secretKey = await open(keyBuffer, { password })

    return new SecureKey(secretKey)
  }

  static async generate (keyFile, { password }) {
    const { publicKey, encryptedKey } = await generateKeys({ password })

    const secretKeyPath = path.join(keyFile)
    const publicKeyPath = path.join(keyFile + '.public')

    try {
      await fs.writeFile(secretKeyPath, z32.encode(encryptedKey), { mode: USER_ONLY_RW })
      await fs.writeFile(publicKeyPath, publicKey, { encoding: 'hex', mode: USER_ONLY_RW })
    } finally {
      encryptedKey.fill(0)
    }
  }

  lock () {
    if (this._cleared) throw new Error('Key has been cleared')

    sodium.sodium_mprotect_noaccess(this.secretKey)
    this._locked = true
  }

  unlock () {
    if (this._cleared) throw new Error('Key has been cleared')

    sodium.sodium_mprotect_readonly(this.secretKey)
    this._locked = false
  }

  clear () {
    this._locked = false
    this._cleared = true

    sodium.sodium_mprotect_readwrite(this.secretKey)
    sodium.sodium_memzero(this.secretKey)
    sodium.sodium_free(this.secretKey)

    this.secretKey = null
  }
}

async function generateKeys ({ password } = {}) {
  const id = Buffer.alloc(8)

  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  const salt = Buffer.alloc(32)
  const kdfOutput = Buffer.alloc(8 + 64 + 32)
  const checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  const params = {
    ops: sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
    mem: sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
  }

  sodium.randombytes_buf(id)
  sodium.randombytes_buf(salt)

  sodium.crypto_sign_keypair(publicKey, secretKey)

  const checkSumData = c.encode(labelledKey, { id, secretKey })

  sodium.crypto_generichash(checkSum, checkSumData)
  sodium.sodium_memzero(checkSumData)

  const payload = c.encode(keyDescriptor, {
    id,
    secretKey,
    checkSum
  })

  sodium.sodium_memzero(secretKey)

  if (password) {
    sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, password, salt, params.ops, params.mem)
    sodium.sodium_memzero(password)
  } else {
    const pwd = await readPassword()
    await confirmPassword(pwd)

    sodium.sodium_mprotect_readwrite(pwd)
    sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, params.ops, params.mem)
    sodium.sodium_memzero(pwd)
    sodium.sodium_free(pwd)
  }

  xor(payload, kdfOutput)
  sodium.sodium_memzero(kdfOutput)

  const encrypted = c.encode(encryptedKey, {
    params,
    salt,
    payload
  })

  sodium.sodium_memzero(payload)

  return {
    id,
    publicKey,
    encryptedKey: encrypted
  }
}

async function open (keyBuffer, { password } = {}) {
  const { params, salt, payload } = c.decode(encryptedKey, keyBuffer)

  const kdfOutput = Buffer.alloc(8 + 64 + 32)

  if (password) {
    sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, password, salt, params.ops, params.mem)
    sodium.sodium_memzero(password)
  } else {
    const pwd = await readPassword()

    sodium.sodium_mprotect_readwrite(pwd)
    sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, params.ops, params.mem)
    sodium.sodium_memzero(pwd)
    sodium.sodium_free(pwd)
  }

  xor(payload, kdfOutput)
  sodium.sodium_memzero(kdfOutput)

  try {
    const { id, secretKey, checkSum } = c.decode(keyDescriptor, payload)

    const checkAgainst = Buffer.alloc(sodium.crypto_generichash_BYTES)
    const checkSumData = c.encode(labelledKey, { id, secretKey })

    sodium.crypto_generichash(checkAgainst, checkSumData)
    sodium.sodium_memzero(checkSumData)

    if (Buffer.compare(checkAgainst, checkSum) !== 0) {
      throw new Error('Key decryption failed')
    }

    const secureKey = sodium.sodium_malloc(64)

    sodium.sodium_mprotect_readwrite(secureKey)
    secureKey.set(secretKey)
    sodium.sodium_mprotect_noaccess(secureKey)

    return secureKey
  } finally {
    sodium.sodium_memzero(payload)
  }
}

// function to accept password from user
async function readPassword (prompt = 'Keypair password: ') {
  process.stdout.write(prompt)

  const pwd = await securePrompt()

  if (pwd.byteLength < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }

  process.stdout.write('\n')

  return pwd
}

async function confirmPassword (pwd) {
  const check = await readPassword('Confirm password: ')

  try {
    sodium.sodium_mprotect_readonly(pwd)
    sodium.sodium_mprotect_readonly(check)

    if (pwd.byteLength !== check.byteLength || !sodium.sodium_memcmp(pwd, check)) {
      sodium.sodium_mprotect_readwrite(pwd)
      sodium.sodium_memzero(pwd)
      sodium.sodium_free(pwd)
      throw new Error('Passwords do not match')
    }

    sodium.sodium_mprotect_noaccess(pwd)
  } finally {
    sodium.sodium_mprotect_readwrite(check)
    sodium.sodium_memzero(check)
    sodium.sodium_free(check)
  }
}

function xor (a, b) {
  if (a.byteLength !== b.byteLength) {
    throw new Error('Buffers should be equal in size')
  }

  for (let i = 0; i < a.length; i++) {
    a[i] ^= b[i]
  }
}
