import {Crypto} from '../src/crypto'

describe('crypto.ts', () => {

  test('base58', () => {
    let data = Buffer.from('73696d706c792061206c6f6e6720737472696e67', 'hex')
    let resultString = Crypto.base58Encode(data)
    expect(resultString).toBe('2cFupjhnEsSn59qHXstmK2ffpLv2')
    
    let data2 = Crypto.base58Decode('2cFupjhnEsSn59qHXstmK2ffpLv2')
    expect(data2.equals(data)).toBe(true)

    let string = 'moky'
    let result = '3oF5MJ'
    let base58Encoded = Crypto.base58Encode(Buffer.from(string, 'utf-8'))
    expect(base58Encoded).toBe(result)
    
    result = 'bW9reQ=='
    let base64Encoded = Buffer.from(string, 'utf-8').toString('base64')
    expect(base64Encoded).toBe(result)
  })

  test('hash256', () => {
    let data = Buffer.from('abc')
    let result = Buffer.from('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'hex')
    let hash = Crypto.hash256(data)
    expect(hash.equals(result)).toBe(true)

    let string = 'moky'
    result = Buffer.from('cb98b739dd699aa44bb6ebba128d20f2d1e10bb3b4aa5ff4e79295b47e9ed76d', 'hex')
    hash = Crypto.hash256(Buffer.from(string, 'utf-8'))
    expect(hash.equals(result)).toBe(true)
  })

  test('ripemd160', () => {
    let data = Buffer.from('abc')
    let result = Buffer.from('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc', 'hex')
    let hash = Crypto.ripemd160(data)
    expect(hash.equals(result)).toBe(true)

    let string = 'moky'
    result = Buffer.from('44bd174123aee452c6ec23a6ab7153fa30fa3b91', 'hex')
    hash = Crypto.ripemd160(Buffer.from(string, 'utf-8'))
    expect(hash.equals(result)).toBe(true)
  })

  test('rsa', () => {

  })
})