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

interface TAI {
    readonly identifier: ID
    readonly data: string
    readonly signature: string // base64
    readonly [key: string]: any
}

interface Profile extends TAI {
    readonly name: string
    readonly key: PublicKey
}

interface EntityDataSource {
    getMeta(entity: Entity | ID): Meta
    getProfile(entity: Entity | ID): Profile
    getName(entity: Entity | ID): string
}

interface User extends Entity {
    readonly publicKey: PublicKey
}

interface LocalUser extends User {
    readonly privateKey: PrivateKey
}

interface UserDataSource {
    getPrivateKey(user: LocalUser | ID): PrivateKey
    getContacts(user: LocalUser | User | ID): ID[]
}

interface Group extends Entity {
    readonly founder: ID
}

interface GroupDataSource {
    getFounder(group: Group | ID): ID
    getOwner(group: Group | ID): ID
    getMembers(group: Group | ID): ID[]
}

export { Entity, Profile, EntityDataSource, User, LocalUser, UserDataSource, Group, GroupDataSource}