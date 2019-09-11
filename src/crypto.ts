import * as CryptoJS from 'crypto-js'
import * as bs58 from 'bs58'
import * as NodeRSA from 'node-rsa'

interface AsymKey {
    readonly algorithm: string
    readonly data: string
}

interface PublicKey extends AsymKey {
    verify(data: Buffer, signature: Buffer): boolean
    encrypt(data: Buffer): Buffer
}

interface PrivateKey extends AsymKey {
    toPublicKey(): PublicKey
    sign(data: Buffer): Buffer
    decrypt(data: Buffer): Buffer
}

class RsaPrivateKey implements PrivateKey {
    readonly algorithm: string
    readonly data: string
    private readonly _key: NodeRSA

    constructor(key: AsymKey) {
        this.algorithm = key.algorithm
        this.data = key.data
        this._key = new NodeRSA(key.data)
        this._key.setOptions({encryptionScheme: 'pkcs1'})
    }

    static create(bits: number = 1024): RsaPrivateKey {
        let key = new NodeRSA({b: bits})
        return new RsaPrivateKey({algorithm: 'RSA' + bits, data: key.exportKey('pkcs8-private-pem')})
    }

    static fromPem(pem: string): RsaPrivateKey {
        let format: NodeRSA.FormatPem = pem.includes('RSA') ? 'pkcs1-private-pem' : 'pkcs8-private-pem'
        let key = new NodeRSA(pem, format)
        return new RsaPrivateKey({algorithm: 'RSA' + key.getKeySize(), data: key.exportKey(format)})
    }

    static fromString(data: string): RsaPrivateKey {
        let object = JSON.parse(data)
        if (!object || !object.algorithm || !object.data) {
            // TODO create base crypto and error module for mkm and dkd
            throw TypeError(`data not AesSymmKey: ${data}`)
        }
        return new RsaPrivateKey(object)
    }

    toPublicKey(): PublicKey {
        let data = this._key.exportKey('pkcs8-public-pem')
        return new RsaPublicKey({algorithm: this.algorithm, data: data})
    }

    sign(data: Buffer): Buffer {
        return this._key.sign(data)
    }
    
    decrypt(encryptedData: Buffer): Buffer {
        return this._key.decrypt(encryptedData)
    }

    toString(): string {
        return JSON.stringify({algorithm: this.algorithm, data: this.data})
    }

    toJSON() {
        return {algorithm: this.algorithm, data: this.data}
    }
}

class RsaPublicKey implements PublicKey {
    readonly algorithm: string
    readonly data: string
    private readonly _key: NodeRSA

    constructor(key: AsymKey) {
        this.algorithm = key.algorithm
        this.data = key.data
        this._key = new NodeRSA(key.data)
        this._key.setOptions({encryptionScheme: 'pkcs1'})
    }

    static fromPem(pem: string): RsaPublicKey {
        let format: NodeRSA.FormatPem = 'pkcs8-public-pem'
        let key = new NodeRSA(pem, format)
        return new RsaPublicKey({algorithm: 'RSA' + key.getKeySize(), data: key.exportKey(format)})
    }

    static fromPrivateKey(key: RsaPrivateKey) {
        return key.toPublicKey()
    }

    static fromString(data: string): RsaPublicKey {
        let object = JSON.parse(data)
        if (!object || !object.algorithm || !object.data) {
            // TODO create base crypto and error module for mkm and dkd
            throw TypeError(`data not AesSymmKey: ${data}`)
        }
        return new RsaPublicKey(object)
    }

    verify(data: Buffer, signature: Buffer): boolean {
        return this._key.verify(data, signature)
    }
    
    encrypt(data: Buffer): Buffer {
        return this._key.encrypt(data)
    }

    toString(): string {
        return JSON.stringify({algorithm: this.algorithm, data: this.data})
    }

    toJSON() {
        return {algorithm: this.algorithm, data: this.data}
    }
}

interface SymmKeyData {
    readonly algorithm: string
    readonly data: string // base64
    readonly iv?: string // base64
}

interface SymmKey extends SymmKeyData {
    encrypt(data: Buffer): Buffer
    decrypt(enc: Buffer): Buffer
}

class AesSymmKey implements SymmKey {
    readonly algorithm: string
    readonly data: string
    readonly iv?: string
    private readonly _key: CryptoJS.LibWordArray
    private readonly _opts: CryptoJS.CipherOption

    constructor(key: SymmKeyData) {
        this.algorithm = key.algorithm
        this.data = key.data
        this.iv = key.iv

        this._key = toLibWordArray(Buffer.from(key.data, 'base64'))
        let length = this._key.words.length * 4
        if (length !== 16 && length !== 24 && length !== 32) {
            throw Error(`AES create invalid bits ${length}`)
        }

        this._opts = {
            iv: key.iv && toLibWordArray(Buffer.from(key.iv, 'base64')) || undefined,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }
    }

    static create(bits: number = 256, key?: Buffer, ivBuffer?: Buffer) {
        key = key || Crypto.random(bits / 8)
        ivBuffer = ivBuffer || Crypto.random(128 / 8)

        if (bits / 8 !== key.length) {
            throw Error(`AES create invalid bits ${bits} !== key.length ${key.length}`)
        }

        let algorithm = 'AES'
        let data = key.toString('base64')
        let iv = ivBuffer.toString('base64')
        return new AesSymmKey({algorithm, data, iv})
    }

    encrypt(data: Buffer): Buffer {
        let encData = CryptoJS.AES.encrypt(toLibWordArray(data), this._key, this._opts)
        return Buffer.from(encData.toString(), 'base64')
    }

    decrypt(encData: Buffer): Buffer {
        let data = CryptoJS.AES.decrypt({ ciphertext: toLibWordArray(encData) }, this._key, this._opts)
        return Buffer.from(data.toString(CryptoJS.enc.Base64), 'base64')
    }

    toString(): string {
        return JSON.stringify({algorithm: this.algorithm, data: this.data})
    }

    toJSON() {
        return {algorithm: this.algorithm, data: this.data, iv: this.iv}
    }
}

class Crypto {

    static base58Decode(address: string): Buffer {
        return bs58.decode(address)
    }

    static base58Encode(address: Buffer): string {
        return bs58.encode(address)
    }

    static sha256(data: Buffer): Buffer {
        return toBuffer(CryptoJS.SHA256(toLibWordArray(data)))
    }

    static ripemd160(data: Buffer): Buffer {
        return toBuffer(CryptoJS.RIPEMD160(toLibWordArray(data)))
    }

    static random(len: number): Buffer {
        let buffer = Buffer.allocUnsafe(len)
        let offset = 0
        while (offset < len) {
            let random = Crypto.randomInt(0xffffffff)
            if (len - offset >= 4) {
                buffer.writeUInt32LE(random, offset)
                offset += 4
            } else {
                while (offset < len) {
                    buffer.writeUInt8(random & 0xff, offset)
                    random >>= 8
                    offset++
                }
            }
        }
        return buffer
    }
    
    static randomInt(max: number) {
        return Math.floor(Math.random() * Math.floor(max));
    }
}

function toLibWordArray(buffer: Buffer): CryptoJS.LibWordArray {
    return CryptoJS.lib.WordArray.create(buffer)
}

function toBuffer(array: CryptoJS.LibWordArray): Buffer {
    let buffer = Buffer.alloc(array.words.length * 4)
    let offset = 0
    for (const value of array.words) {
        buffer.writeInt32BE(value, offset)
        offset += 4
    }
    return buffer
}

export { Crypto, PublicKey, PrivateKey, RsaPrivateKey, RsaPublicKey, SymmKey, AesSymmKey }