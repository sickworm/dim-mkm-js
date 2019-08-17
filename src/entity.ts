import { ID } from './identifier'
import { Meta } from './meta'
import { PublicKey, PrivateKey } from './crypto'

/**
    Entity (Account/Group)
    ~~~~~~~~~~~~~~~~~~~~~~

    Base class of Account and Group, ...
 */
interface Entity {
    readonly identifier: ID
}

interface Profile {
    readonly identifier: ID
    readonly name?: string
    readonly avatar?: string
    readonly [key: string]: any
}

interface EntityDataSource {
    getMeta(entity: Entity): Meta
    getProfile(entity: Entity): Profile
    getName(entity: Entity): string
}

interface Account extends Entity {
    readonly publicKey: PublicKey
}

interface Group extends Entity {
    readonly founder: ID
}

interface GroupDataSource {
    getFounder(group: ID): ID
    getOwner(group: ID): ID
    getMembers(group: ID): ID[]
}

interface User extends Account {
    readonly privateKey: PrivateKey
}

interface UserDataSource {
    getPrivateKey(user: User): PrivateKey
    getContacts(user: User): Account[]
}

export { Entity, Profile, EntityDataSource, Account, Group, GroupDataSource, User, UserDataSource }