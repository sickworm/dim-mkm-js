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
    
    decrypt(data: Buffer): Buffer {
        return this._key.decrypt(data)
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

    static fromPem(pem: string) {
        let format: NodeRSA.FormatPem = 'pkcs8-public-pem'
        let key = new NodeRSA(pem, format)
        return new RsaPrivateKey({algorithm: 'RSA' + key.getKeySize(), data: key.exportKey(format)})
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

class Crypto {

    static base58Decode(address: string): Buffer {
        return bs58.decode(address)
    }

    static base58Encode(address: Buffer): string {
        return bs58.encode(address)
    }

    static hash256(data: Buffer): Buffer {
        return Crypto.toBuffer(CryptoJS.SHA256(Crypto.toLibWordArray(data)))
    }

    static ripemd160(data: Buffer): Buffer {
        return Crypto.toBuffer(CryptoJS.RIPEMD160(Crypto.toLibWordArray(data)))
    }

    private static toLibWordArray(buffer: Buffer): CryptoJS.LibWordArray {
        return CryptoJS.lib.WordArray.create(buffer)
    }

    private static toBuffer(array: CryptoJS.LibWordArray): Buffer {
        let buffer = Buffer.alloc(array.words.length * 4)
        let offset = 0
        for (const value of array.words) {
            buffer.writeInt32BE(value, offset)
            offset += 4
        }
        return buffer
    }
}

export { Crypto, PublicKey, PrivateKey, SymmKey, RsaPrivateKey, RsaPublicKey }