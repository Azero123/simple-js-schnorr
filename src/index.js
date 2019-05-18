const bigInt = require('big-integer')
const base58 = require('bs58')
const crypto = require('crypto')
const secp256k1 = require('simple-js-secp256k1')
const ModPoint = require('simple-js-ec-math').ModPoint

let hex = { '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, a: 10, b: 11, c: 12, d: 13, e: 14, f: 15 }

const sha256 = require('simple-js-sha2-256')
const ripemd160 = data => crypto.createHash('ripemd160').update(data, 'hex').digest('hex').toString()

const hexStringToBinaryString = s => {
  s = s.toLowerCase()
  const len = s.length;
  var data = [];
  for (let i = 0; i < len; i += 2) {
    data[i / 2] = String.fromCharCode((hex[s[i]] << 4) + (hex[s[i + 1]]));
  }
  return data.join('');
}

const binSha256 = data => sha256(hexStringToBinaryString(data))
const binRipemd160 = data => ripemd160(data)

class Identity {
  static new(curve = secp256k1) {
    return Identity.fromKey(curve.modSet.random(), curve)
  }

  static fromKey(key, curve = secp256k1) {
    let _key
    if (key instanceof bigInt) {
      _key = key
      key = key.toString(16)
    }
    else {
      _key = bigInt(key, 16)
    }
    const wallet = new Identity()
    wallet.curve = curve
    wallet.key = key
    wallet._key = _key
    return wallet
  }

  static fromWif(wif, curve = secp256k1) {
    const hexWif = base58.decode(wif).toString('hex')
    const key = hexWif.substring(2, hexWif.length - 8)
    const wallet = Identity.fromKey(key, curve)
    if (wallet.wif !== wif) {
      throw 'invalid wif'
    }
    return wallet
  }

  static fromSec1(sec1, curve = secp256k1) {
    const identity = new Identity()
    identity.curve = curve
    identity._publicPoint = ModPoint.fromSec1(sec1, curve)
    if (
      !secp256k1.verify(identity.publicPoint)
    ) {
      throw 'invalid address' + (mode === '03' || mode === '02') ? ' compressed addresses not yet supported' : ''
    }
    return identity
  }

  static fromPublicPoint(publicPoint, curve = secp256k1) {
    const wallet = new Identity()
    wallet.curve = curve
    wallet._publicPoint = publicPoint
    return wallet
  }

  sign(message, k = this.curve.modSet.random()) {
    if (!(k instanceof bigInt)) {
      k = bigInt(k, 16)
    }
    const hash = sha256(message)
    const r = this.curve.multiply(this.curve.g, k)
    const e = bigInt(sha256(hash+r.sec1Compressed+this.sec1Compressed), 16)
    const s = k.subtract(this.curve.modSet.add(e, this._key)).add(secp256k1.n).mod(secp256k1.n)

    return {
      r: r,
      s: s.toString(16)
    }
  }
  
  verify(message, signature) {
    const hash = sha256(message)
    const e = bigInt(sha256(hash+signature.r.sec1Compressed+this.sec1Compressed), 16)
    const eG = this.curve.multiply(this.curve.g, e)
    const xG = this.publicPoint
    const kG = signature.r
    const exG = this.curve.add(eG, xG)
    const sG = this.curve.multiply(this.curve.g, bigInt(signature.s, 16))
    const sG1 = this.curve.subtract(kG, exG)
    return sG1.toString() === sG.toString()
  }

  static validateAddress(address) {
    if (address.length !== 34) {
      throw 'invalid address'
    }
    address = base58.decode(address).toString('hex')
    const addressChecksum = binSha256(binSha256(address.substr(0,42))).substr(0, 8)
    const checksum = address.substr(42,50)
    return addressChecksum === checksum
  }

  keyExchange(identity) {
    const pub = this.diffieHellman(identity)
    const sharedIdentity = Identity.fromPublicPoint(pub, this.curve)
    const tempSecretPublicKey = sharedIdentity.publicPoint.toJSON()
    return tempSecretPublicKey.x
  }

  diffieHellman(identity) {
    if (this.key) {
      return this.curve.multiply(identity.publicPoint, this._key)
    }
    throw 'diffie-hellman key exchanges requires a private key instantiated identity'
  }

  get wif() {
    if (this._wif) {
      return this._wif
    }
    const formatted = `80${this.key}`
    const checksum = binSha256(binSha256(formatted)).substr(0, 8)
    return this._wif = base58.encode(Buffer.from(`${formatted}${checksum}`, 'hex'))
  }

  get publicPoint() {
    if (this._publicPoint) {
      return this._publicPoint
    }
    return this._publicPoint = this.curve.multiply(this.curve.g, this._key)
  }

  get sec1Compressed() {
    return this.publicPoint.sec1Compressed
  }

  get sec1Uncompressed() {
    return this.publicPoint.sec1Uncompressed
  }

  get address() {
    if (this._address) {
      return this._address
    }
    const formatted = `00${binRipemd160(binSha256(this.sec1Uncompressed))}`
    const checksum = binSha256(binSha256(formatted)).substr(0, 8)
    return this._address = base58.encode(Buffer.from(`${formatted}${checksum}`, 'hex'))
  }

  get compressAddress() {
    if (this._compressAddress) {
      return this._compressAddress
    }
    const formatted = `00${binRipemd160(binSha256(this.sec1Compressed))}`
    const checksum = binSha256(binSha256(formatted)).substr(0, 8)
    return this._compressAddress = base58.encode(Buffer.from(`${formatted}${checksum}`, 'hex'))
  }
}
module.exports = Identity