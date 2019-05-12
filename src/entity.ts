import { ID } from './identifier'
import { Meta } from './meta'
import { PublicKey, PrivateKey } from './crypto';

/**
    Entity (Account/Group)
    ~~~~~~~~~~~~~~~~~~~~~~

    Base class of Account and Group, ...
 */
class Entity {
    readonly identifier: ID

    public constructor(identifier: ID) {
        this.identifier = identifier
    }

    public toString(): string {
        // TODO delegate?
        let name = this.identifier.name || this.identifier.address.string
        return `<${this.constructor.name}: ${this.identifier}(${this.identifier.address.network}|${this.identifier.address.code}) "${name}"`
    }
}

interface Profile {
    identifier: ID
    name?: string
    avatar?: string
    [key: string]: any
}

interface EntityDataSource {
    getMeta(entity: Entity): Meta
    getProfile(entity: Entity): Profile
    getName(entity: Entity): string
}

class Account extends Entity {
    publicKey: PublicKey

    public constructor(identifier: ID, publicKey: PublicKey) {
        super(identifier);
        this.publicKey = publicKey
    }
}

class Group extends Entity {
    founder: ID

    public constructor(identifier: ID, founder: ID) {
        super(identifier);
        this.founder = founder
    }
}

interface GroupDataSource {
    getFounder(group: Group): ID
    getOwner(group: Group): ID
    getMembers(group: Group): Array<ID>
}

class User extends Account {
    privateKey: PrivateKey

    public constructor(identifier: ID, publicKey: PublicKey, privateKey: PrivateKey) {
        super(identifier, publicKey)
        this.privateKey = privateKey
    }
}

interface UserDataSource {
    getPrivateKey(user: User): PrivateKey // TODO user ID ?
    getContacts(user: User): Array<Account>
}

export { Entity, Profile, EntityDataSource, Account, Group, GroupDataSource, User, UserDataSource }