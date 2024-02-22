const c = require('compact-encoding')

const labelledKey = {
  preencode (state, k) {
    c.fixed(8).preencode(state, k.id)
    c.fixed64.preencode(state, k.secretKey)
  },
  encode (state, k) {
    c.fixed(8).encode(state, k.id)
    c.fixed64.encode(state, k.secretKey)
  },
  decode (state) {
    throw new Error('No decoder')
  }
}

const keyDescriptor = {
  preencode (state, s) {
    c.fixed(8).preencode(state, s.id)
    c.fixed64.preencode(state, s.secretKey)
    c.fixed32.preencode(state, s.checkSum)
  },
  encode (state, s) {
    c.fixed(8).encode(state, s.id)
    c.fixed64.encode(state, s.secretKey)
    c.fixed32.encode(state, s.checkSum)
  },
  decode (state) {
    return {
      id: c.fixed(8).decode(state),
      secretKey: c.fixed64.decode(state),
      checkSum: c.fixed32.decode(state)
    }
  }
}

const kdfParams = {
  preencode (state, p) {
    c.uint64.preencode(state, p.ops)
    c.uint64.preencode(state, p.mem)
  },
  encode (state, p) {
    c.uint64.encode(state, p.ops)
    c.uint64.encode(state, p.mem)
  },
  decode (state) {
    return {
      ops: c.uint64.decode(state),
      mem: c.uint64.decode(state)
    }
  }
}

const encryptedKey = {
  preencode (state, s) {
    kdfParams.preencode(state, s.params)
    c.fixed32.preencode(state, s.salt)
    c.buffer.preencode(state, s.payload)
  },
  encode (state, s) {
    kdfParams.encode(state, s.params)
    c.fixed32.encode(state, s.salt)
    c.buffer.encode(state, s.payload)
  },
  decode (state) {
    return {
      params: kdfParams.decode(state),
      salt: c.fixed32.decode(state),
      payload: c.buffer.decode(state)
    }
  }
}

module.exports = {
  labelledKey,
  keyDescriptor,
  kdfParams,
  encryptedKey
}
