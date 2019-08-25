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

interface SymmKey {
    readonly algorithm: string
    readonly data: string

    encrypt(data: Buffer): Buffer
    decrypt(enc: Buffer): Buffer
}

class RsaPrivateKey implements PrivateKey {
    readonly algorithm: string
    readonly data: string
    private readonly _key: NodeRSA

    constructor(key: AsymKey) {
        this.algorithm = key.algorithm
        this.data = key.data
        this._key = new NodeRSA(key.data)
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
}

class RsaPublicKey implements PublicKey {
    readonly algorithm: string
    readonly data: string
    private readonly _key: NodeRSA

    constructor(key: AsymKey) {
        this.algorithm = key.algorithm
        this.data = key.data
        this._key = new NodeRSA(key.data)
    }

    static fromPem(pem: string): RsaPublicKey {
        let format: NodeRSA.FormatPem = 'pkcs8-public-pem'
        let key = new NodeRSA(pem, format)
        return new RsaPublicKey({algorithm: 'RSA' + key.getKeySize(), data: key.exportKey(format)})
    }

    static fromPrivateKey(key: RsaPrivateKey) {
        return key.toPublicKey()
    }

    verify(data: Buffer, signature: Buffer): boolean {
        return this._key.verify(data, signature)
    }
    
    encrypt(data: Buffer): Buffer {
        return this._key.encrypt(data)
    }
}

class AesSymmKey implements SymmKey {
    readonly algorithm: string
    readonly data: string
    private readonly _key: CryptoJS.LibWordArray
    private readonly _opts: CryptoJS.CipherOption

    constructor(algorithm: string, data: string) {
        this.algorithm = algorithm
        this.data = data

        let json = JSON.parse(data)
        this._key = toLibWordArray(Buffer.from(json.key, 'base64'))
        this._opts = {
            iv: toLibWordArray(Buffer.from(json.iv, 'base64')),
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }
    }

    static create(bits: number = 256, key?: Buffer, iv?: Buffer) {
        if (bits !== 128 && bits !== 192 && bits !== 256) {
            throw Error(`AES create invalid bits ${bits}`)
        }
        key = key || Crypto.random(bits / 8)
        iv = iv || Crypto.random(128 / 8)

        let algorithm = 'AES' + bits
        let data = JSON.stringify({
            key: key.toString('base64'),
            iv: iv.toString('base64')
        })
        return new AesSymmKey(algorithm, data)
    }

    static fromString(data: string): AesSymmKey {
        let object = JSON.parse(data)
        if (!object || !object.algorithm || !object.data) {
            // TODO create base crypto and error module for mkm and dkd
            throw TypeError(`data not AesSymmKey: ${data}`)
        }
        return object as AesSymmKey
    }

    static toString(): string {
        return JSON.stringify(this)
    }

    encrypt(data: Buffer): Buffer {
        let encData = CryptoJS.AES.encrypt(toLibWordArray(data), this._key, this._opts)
        return Buffer.from(encData.toString(), 'base64')
    }

    decrypt(encData: Buffer): Buffer {
        let data = CryptoJS.AES.decrypt({ ciphertext: toLibWordArray(encData) }, this._key, this._opts)
        return Buffer.from(data.toString(CryptoJS.enc.Base64), 'base64')
    }
}

class Crypto {

    static base58Decode(address: string): Buffer {
        return bs58.decode(address)
    }

    static base58Encode(address: Buffer): string {
        return bs58.encode(address)
    }

    static hash256(data: Buffer): Buffer {
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