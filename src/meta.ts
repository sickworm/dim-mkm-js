import { ID } from './identifier'
/**
 *  Account/Group Meta data
 *
 *      data format: {
 *          version: 1,          // algorithm version
 *          seed: "moKy",        // user/group name
 *          key: "{public key}", // PK = secp256k1(SK);
 *          fingerprint: "..."   // CT = sign(seed, SK);
 *      }
 *
 *      algorithm:
 *          fingerprint = sign(seed, SK);
 *
 *          CT      = fingerprint; // or key.data for BTC address
 *          hash    = ripemd160(sha256(CT));
 *          code    = sha256(sha256(network + hash)).prefix(4);
 *          address = base58_encode(network + hash + code);
 *          number  = uint(code);
 */

const Version = {
    MKM: 0x01,
    BTC: 0x02,
    EX_BTC: 0x03,
    DEFAULT: 0x01
}

interface Meta {
    readonly version: number
    readonly publicKey: string
    readonly seed: string
    readonly fingerprint: Buffer
}

interface MetaDataSource {
    getMeta(identifier: ID): Meta
}

export {Version, Meta, MetaDataSource}