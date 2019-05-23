import { ID } from './identifier'
import { Crypto, PrivateKey, PublicKey } from './crypto';
import { Address, NetworkType } from './address';
import { verify } from 'crypto';
import { identifier } from '@babel/types';

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

    constructor(meta: MetaConstructor) {
        this.version = meta.version
        this.publicKey = meta.publicKey
        this.seed = meta.seed
        this.fingerprint = meta.fingerprint
    }

    static fromKeyAndSeed(privateKey: PrivateKey, seed: string,
        version: MetaVersion = MetaVersion.DEFAULT): Meta {
        let publicKey = privateKey.toPublicKey()
        let fingerprint = version === MetaVersion.BTC ?
            publicKey.data :
            privateKey.sign(Buffer.from(seed, 'utf-8')).toString('base64')
        return new Meta({version, publicKey, seed, fingerprint})
    }
    
    matches(object: PublicKey | ID | Address): boolean {
        if (object instanceof ID) {
            let identifier = this.buildId(object.type)
            return identifier.equals(object)
        } else if (object instanceof Address) {
            let address
        } else if (object.algorithm && object.data) { // PublicKey
            return (this.publicKey.algorithm === object.algorithm) && (this.publicKey.data === object.data)
        }
        return false;
    }

    buildId(network: NetworkType): ID {
        let address = this.buildAddress(network)
        if (this.version === MetaVersion.BTC) {
            return ID.fromAddress(address)
        } else {
            // MKM & ExBTC
            return ID.fromAddress(address, this.seed)
        }
    }

    buildAddress(network: NetworkType): Address {
        if (this.version === MetaVersion.MKM) {
            return Address.fromFingerprint(this.fingerprint, network)
        } else {
            // BTC & ExBTC
            return Address.fromFingerprint(this.publicKey.data, network)
        }
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