const path = require('path')
const fs = require('fs').promises
const test = require('brittle')

const SecureKey = require('../')

test('basic', async t => {
  const file = path.resolve(__dirname, 'keys', 'test-' + Date.now().toString())

  await SecureKey.generate(file, { password: Buffer.from('password') })

  const pk = Buffer.from(await fs.readFile(file + '.public', { encoding: 'hex' }), 'hex')
  const k = await SecureKey.open(file, { password: Buffer.from('password') })

  k.unlock()

  t.alike(k.publicKey, pk)
  t.ok(k.secretKey)
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
