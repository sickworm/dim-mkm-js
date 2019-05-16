import { ID } from './identifier'
import { Crypto, PrivateKey, PublicKey } from './crypto';
import { Address, NetworkType } from './address';

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
class Meta implements MetaConstructor{
    readonly version: MetaVersion
    readonly publicKey: PublicKey
    readonly seed: string
    readonly fingerprint: string

    public constructor(meta: MetaConstructor) {
        this.version = meta.version
        this.publicKey = meta.publicKey
        this.seed = meta.seed
        this.fingerprint = meta.fingerprint
    }

    public static fromKeyAndSeed(privateKey: PrivateKey, seed: string,
        version: MetaVersion = MetaVersion.DEFAULT): Meta {
        let publicKey = privateKey.toPublicKey()
        let fingerprintData = version === MetaVersion.BTC ?
            publicKey.toBuffer() :
            privateKey.sign(Buffer.from(seed, 'utf-8'))
        let fingerprint = Crypto.base58Encode(fingerprintData)
        return new Meta({version, publicKey, seed, fingerprint})
    }
    
    public matches(object: PublicKey | ID | Address | NetworkType): boolean {
        return true;
    }
}

interface MetaConstructor {
    readonly version: MetaVersion
    readonly publicKey: PublicKey
    readonly seed: string
    readonly fingerprint: string
}

enum MetaVersion {
    MKM = 0x01,
    BTC = 0x02,
    EX_BTC = 0x03,
    DEFAULT = 0x01
}

interface MetaDataSource {
    getMeta(identifier: ID): Meta
}

export {MetaVersion, Meta, MetaDataSource}