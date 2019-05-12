import {ID} from './identifier'
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
class Meta implements MetaConstructor {
    static readonly VERSION_MKM: number  = 0x01
    static readonly VERSION_BTC: number  = 0x02
    static readonly VERSION_EX_BTC: number  = 0x03
    static readonly VERSION_DEFAULT: number  = Meta.VERSION_MKM
    
    readonly version: number
    readonly publicKey: string
    readonly seed: string
    readonly fingerprint: Buffer

    public constructor(meta: MetaConstructor) {
        this.version = meta.version
        this.publicKey = meta.publicKey
        this.seed = meta.seed
        this.fingerprint = meta.fingerprint
    }
}

interface MetaConstructor {
    version: number
    publicKey: string
    seed: string
    fingerprint: Buffer
}

interface MetaDataSource {
    getMeta(identifier: ID): Meta
}

export {Meta, MetaDataSource}