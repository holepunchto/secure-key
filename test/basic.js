const path = require('path')
const fs = require('fs').promises
const test = require('brittle')
const tmp = require('test-tmp')

const SecureKey = require('../')

test('basic', async t => {
  const keysDir = await tmp(t)

  const file = path.join(keysDir, 'test-key')
  await SecureKey.generate(file, { password: Buffer.from('password') })

  const pk = Buffer.from(await fs.readFile(file + '.public', { encoding: 'hex' }), 'hex')
  const k = await SecureKey.open(file, { password: Buffer.from('password'), protected: true })

  k.unlock()

  t.alike(k.publicKey, pk)
  t.ok(k.secretKey)
  t.ok(k.secretKey.secure)
  t.absent(k._locked)
  t.absent(k._cleared)

  k.lock()

  t.ok(k._locked)
  t.absent(k._cleared)

  k.clear()

  t.ok(k.publicKey)
  t.absent(k.secretKey)
  t.absent(k._locked)
  t.ok(k._cleared)
})

test('basic - unprotected', async t => {
  const keysDir = await tmp(t)

  const file = path.join(keysDir, 'test-key')
  await SecureKey.generate(file, { password: Buffer.from('password') })

  const pk = Buffer.from(await fs.readFile(file + '.public', { encoding: 'hex' }), 'hex')
  const k = await SecureKey.open(file, { password: Buffer.from('password') })

  t.exception(() => k.unlock())

  t.alike(k.publicKey, pk)
  t.ok(k.secretKey)
  t.absent(k.secretKey.secure)
  t.absent(k._locked)
  t.absent(k._cleared)

  t.exception(() => k.lock())

  t.absent(k._locked)
  t.absent(k._cleared)

  k.clear()

  t.ok(k.publicKey)
  t.absent(k.secretKey)
  t.absent(k._locked)
  t.ok(k._cleared)
})
