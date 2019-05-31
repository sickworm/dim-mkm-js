import {Address, NetworkType} from './address'

class ID implements IDConstructor {
    readonly string: string
    readonly name?: string
    readonly address: Address
    readonly terminal?: string

    get number(): number {
        return this.address.code
    }

    get type(): NetworkType {
        return this.address.network
    }

    private constructor(id: IDConstructor) {
        this.string  = id.string
        this.name  = id.name
        this.address  = id.address
        this.terminal  = id.terminal
    }

    static fromString(string: string): ID {
        let pair = string.split('/')
        let terminal = undefined
        if (pair.length > 1) {
            terminal = pair[1]
        }

        let address
        let name = ""
        pair = pair[0].split('@', 2)
        if (pair.length > 1) {
            name = pair[0]
            address = Address.fromString(pair[1])
        } else {
            address = Address.fromString(pair[0])
        }
        return new ID({string, address, name, terminal})
    }

    static fromAddress(address: Address, name?: string): ID {
        let string
        if (!name) {
            string = address.string
        } else {
            string = name + '@' + address.string
        }
        return new ID({string, name, address})
    }

    equals(identifier: ID): boolean {
        return this.name === identifier.name && this.address.euqals(identifier.address)
    }

    toString(): string {
        return this.string
    }
}

interface IDConstructor {
    readonly string: string
    readonly name?: string
    readonly address: Address
    readonly terminal?: string
}

export { ID }