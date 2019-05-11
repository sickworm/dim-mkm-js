
/**
    Entity (Account/Group)
    ~~~~~~~~~~~~~~~~~~~~~~

    Base class of Account and Group, ...
 */
class Entity {
    identifier: ID

    public constructor(identifier: ID) {
        this.identifier = identifier
    }

    public toString(): string {
        // TODO delegate?
        let name = this.identifier.name || this.identifier.address.string
        return `<${this.constructor.name}: ${this.identifier}(${this.identifier.address.network}|${this.identifier.address.number}) "${name}"`
    }
}