import {Crypto} from '../src/crypto'

describe('crypto.ts', () => {

  test('base58', () => {
    let data = Buffer.from('73696d706c792061206c6f6e6720737472696e67', 'hex')
    let string = Crypto.base58Encode(data)
    expect(string).toBe('2cFupjhnEsSn59qHXstmK2ffpLv2')
    
    let data2 = Crypto.base58Decode('2cFupjhnEsSn59qHXstmK2ffpLv2')
    expect(data2.equals(data)).toBe(true)
  })

  test('hash256', () => {
    let data = Buffer.from('abc')
    let result = Buffer.from('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'hex')
    let hash = Crypto.hash256(data)
    expect(hash.equals(result)).toBe(true)
  })

  test('ripemd160', () => {
    let data = Buffer.from('abc')
    let result = Buffer.from('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc', 'hex')
    let hash = Crypto.ripemd160(data)
    expect(hash.equals(result)).toBe(true)
  })
})