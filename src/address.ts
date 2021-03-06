import {Crypto} from './crypto'

/**
 *  enum MKMNetworkID
 *
 *  abstract A network type to indicate what kind the entity is.
 *
 *  discussion An address can identify a person, a group of people,
 *      a team, even a thing.
 *
 *      MKMNetwork_Main indicates this entity is a person's account.
 *      An account should have a public key, which proved by meta data.
 *
 *      MKMNetwork_Group indicates this entity is a group of people,
 *      which should have a founder (also the owner), and some members.
 *
 *      MKMNetwork_Moments indicates a special personal social network,
 *      where the owner can share informations and interact with its friends.
 *      The owner is the king here, it can do anything and no one can stop it.
 *
 *      MKMNetwork_Polylogue indicates a virtual (temporary) social network.
 *      It's created to talk with multi-people (but not too much, e.g. less than 100).
 *      Any member can invite people in, but only the founder can expel member.
 *
 *      MKMNetwork_Chatroom indicates a massive (persistent) social network.
 *      It's usually more than 100 people in it, so we need administrators
 *      to help the owner to manage the group.
 *
 *      MKMNetwork_SocialEntity indicates this entity is a social entity.
 *
 *      MKMNetwork_Organization indicates an independent organization.
 *
 *      MKMNetwork_Company indicates this entity is a company.
 *
 *      MKMNetwork_School indicates this entity is a school.
 *
 *      MKMNetwork_Government indicates this entity is a government department.
 *
 *      MKMNetwork_Department indicates this entity is a department.
 *
 *      MKMNetwork_Thing this is reserved for IoT (Internet of Things).
 *
 *  Bits:
 *      0000 0001 - this entity's branch is independent (clear division).
 *      0000 0010 - this entity can contains other group (big organization).
 *      0000 0100 - this entity is top organization.
 *      0000 1000 - (Main) this entity acts like a human.
 *
 *      0001 0000 - this entity contains members (Group)
 *      0010 0000 - this entity needs other administrators (big organization)
 *      0100 0000 - this is an entity in reality.
 *      1000 0000 - (IoT) this entity is a 'Thing'.
 *
 *      (All above are just some advices to help choosing numbers :P)
 */
class NetworkType {
    static readonly BTCMain        = new NetworkType(0x00) // 0000 0000
    //BTCTest      (0x6f), // 0110 1111

    /**
     *  Person Account
     */
    static readonly Main           = new NetworkType(0x08) // 0000 1000 (Person)

    /**
     *  Virtual Groups
     */
    static readonly Group          = new NetworkType(0x10) // 0001 0000 (Multi-Persons)

    //Moments      = 0x18, // 0001 1000 (Twitter)
    static readonly Polylogue      = new NetworkType(0x10) // 0001 0000 (Multi-Persons Chat, N < 100)
    static readonly Chatroom       = new NetworkType(0x30) // 0011 0000 (Multi-Persons Chat, N >= 100)

    /**
     *  Social Entities in Reality
     */
    //SocialEntity = 0x50, // 0101 0000

    //Organization = 0x74, // 0111 0100
    //Company      = 0x76, // 0111 0110
    //School       = 0x77, // 0111 0111
    //Government   = 0x73, // 0111 0011
    //Department   = 0x52, // 0101 0010

    /**
     *  Network
     */
    static readonly Provider       = new NetworkType(0x76) // 0111 0110 (Service Provider)
    static readonly Station        = new NetworkType(0x88) // 1000 1000 (Server Node)

    /**
     *  Internet of Things
     */
    static readonly Thing          = new NetworkType(0x80) // 1000 0000 (IoT)
    static readonly Robot          = new NetworkType(0xC8) // 1100 1000

    value: number

    private constructor(value: number) {
        this.value = value
    }

    static fromNumber(value: number): NetworkType {
        switch(value) {
            case this.BTCMain.value: return this.BTCMain
            case this.Main.value: return this.Main
            case this.Group.value: return this.Group
            case this.Polylogue.value: return this.Polylogue
            case this.Chatroom.value: return this.Chatroom
            case this.Provider.value: return this.Provider
            case this.Station.value: return this.Station
            case this.Thing.value: return this.Thing
            case this.Robot.value: return this.Robot
            default:
                throw new Error(`invalid NetworkType ${value}`)
        }
    }

    isCommunicator(): boolean {
        return (this.value & NetworkType.Main.value) !== 0 || this.value === NetworkType.BTCMain.value;
    }

    isPerson(): boolean {
        return this.value === NetworkType.Main.value || this.value === NetworkType.BTCMain.value;
    }

    isGroup(): boolean {
        return (this.value & NetworkType.Group.value) !== 0;
    }

    isStation(): boolean {
        return this.value === NetworkType.Station.value
    }

    isProvider(): boolean {
        return this.value === NetworkType.Provider.value
    }

    isThing(): boolean {
        return (this.value & NetworkType.Provider.value) !== 0
    }

    isRobot(): boolean {
        return this.value === NetworkType.Robot.value
    }
}

/**
 *  Address like BitCoin
 *
 *      data format: "network+digest+checkcode"
 *          network    --  1 byte
 *          digest     -- 20 bytes
 *          check_code --  4 bytes
 *
 *      algorithm:
 *          fingerprint = sign(seed, SK);
 *          digest      = ripemd160(sha256(fingerprint));
 *          check_code  = sha256(sha256(network + digest)).prefix= 4;
 *          address     = base58_encode(network + digest + check_code);
 */
class Address implements AddressConstructor {
    static readonly ANYWHERE = new Address({string: 'anywhere', network: NetworkType.Main, code: 9527})
    static readonly EVERYWHERE = new Address({string: 'everywhere', network: NetworkType.Group, code: 9527})

    readonly string: string
    readonly network: NetworkType
    readonly code: number

    private constructor(address: AddressConstructor) {
        this.string = address.string
        this.network = address.network
        this.code = address.code
    }

    isBoardcast(): boolean {
        return this === Address.EVERYWHERE || this === Address.ANYWHERE
    }

    euqals(address: Address): boolean {
        return this.string === address.string
    }

    toString(): string {
        return this.string
    }

    /**
     *  Copy address data
     *
     *  @param string - Encoded address string
     */
    static fromString(string: string): Address {
        let data = Crypto.base58Decode(string)
        if (data.length != 25) {
            throw Error('Address fromString data.length != 25')
        }
        let network = NetworkType.fromNumber(data[0])
        let code = Address.userNumber(Crypto.sha256(Crypto.sha256(data.slice(0, 21))))
        return new Address({string, network, code})
    }

    /**
     *  Generate address with fingerprint and network ID
     *
     *  @param fingerprint = sign(seed, PK)
     *  @param network - network ID
     */
    static fromFingerprint(fingerprint: string, network: NetworkType): Address {
        let digest = Crypto.ripemd160(Crypto.sha256(Buffer.from(fingerprint, 'base64')))
        let head = Buffer.alloc(21)
        head[0] = network.value
        digest.copy(head, 1)
        let cc = Crypto.sha256(Crypto.sha256(head))
        let code = Address.userNumber(cc)
        let data = Buffer.concat([head, cc])
        let string = Crypto.base58Encode(data)
        return new Address({string, network, code})
    }

    private static userNumber(cc: Buffer): number {
        return ((cc[3] & 0xFF) << 24 >>> 0) + ((cc[2] & 0xFF) << 16 >>> 0)  +
            ((cc[1] & 0xFF) << 8 >>> 0)  + ((cc[0] & 0xFF) >>> 0) ;
    }
}

interface AddressConstructor {
    string: string
    network: NetworkType
    code: number
}

export { NetworkType, Address }
