import CryptoJS = require('crypto-js')
import bs58 = require('bs58')

export class Crypto {
    public static base58Decode(address: string): Buffer {
        return bs58.decode(address)
    }

    public static base58Encode(address: Buffer): string {
        return bs58.encode(address)
    }

    public static hash256(data: Buffer): Buffer {
        return Crypto.toBuffer(CryptoJS.SHA256(Crypto.toLibWordArray(data)))
    }

    public static ripemd160(data: Buffer): Buffer {
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