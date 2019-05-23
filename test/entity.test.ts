import { Address, NetworkType } from '../src/address'
import { ID } from '../src/identifier'
import { Account, User } from '../src/entity'
import { RsaPrivateKey } from '../src/crypto';
import { Meta } from '../src/meta';

describe('entity.ts', () => {

    test('address', () => {
        let address = Address.fromString('4WDfe3zZ4T7opFSi3iDAKiuTnUHjxmXekk')
        expect(address.network).toBe(8)
        expect(address.code).toBe(1840839527)

        address = Address.fromString('4DnqXWdTV8wuZgfqSCX9GjE2kNq7HJrUgQ')
        expect(address.network).toBe(8)
        expect(address.code).toBe(4049699527)
    })

    test('id', () => {
        let identifier = ID.fromString('moki@4WDfe3zZ4T7opFSi3iDAKiuTnUHjxmXekk')
        expect(identifier.number).toBe(1840839527)

        identifier = ID.fromString('moky@4DnqXWdTV8wuZgfqSCX9GjE2kNq7HJrUgQ')
        expect(identifier.number).toBe(4049699527)

        expect(identifier).toEqual(ID.fromString('moky@4DnqXWdTV8wuZgfqSCX9GjE2kNq7HJrUgQ'))
    })

    test('meta', () => {
        let privateKey = RsaPrivateKey.create()
        let publicKey = privateKey.toPublicKey()
        let seed = 'moky'
        let meta = Meta.fromKeyAndSeed(privateKey, seed)
        let identifier = meta.buildId(NetworkType.Main)
        let user: User = { identifier, privateKey, publicKey }
    })

    test('entity', () => {
        let privateKey = RsaPrivateKey.create()
        let publicKey = privateKey.toPublicKey()
        let identifier = ID.fromString('moky@4DnqXWdTV8wuZgfqSCX9GjE2kNq7HJrUgQ')
        let account: Account = {identifier, publicKey}
        let user: User = {identifier, publicKey, privateKey}
        expect(account.identifier.number).toBe(4049699527)
        expect(user.identifier.number).toBe(4049699527)
        expect(account.identifier).toEqual(user.identifier)
    })
})