import { Crypto, RsaPrivateKey, RsaPublicKey, AesSymmKey } from '../src/crypto'
import * as CryptoJS from 'crypto-js'

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

    test('sha256', () => {
        let data = Buffer.from('abc')
        let result = Buffer.from('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'hex')
        let hash = Crypto.sha256(data)
        expect(hash.equals(result)).toBe(true)

        let string = 'moky'
        result = Buffer.from('cb98b739dd699aa44bb6ebba128d20f2d1e10bb3b4aa5ff4e79295b47e9ed76d', 'hex')
        hash = Crypto.sha256(Buffer.from(string, 'utf-8'))
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

    test('RSA generate', () => {
        let sk = RsaPrivateKey.create();
        let pk = sk.toPublicKey();

        let text = 'moky'
        let textData = Buffer.from(text, 'utf-8')
        let encrypted = pk.encrypt(textData)
        let decrypted = sk.decrypt(encrypted)
        expect(decrypted.toString('utf-8')).toBe(text)

        let signature = sk.sign(textData)
        expect(pk.verify(textData, signature)).toBe(true)
    })

    test('RSA import encrypt', () => {
        let sk = RsaPrivateKey.fromPem(`
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQDET7fvLupUBUc6ImwJejColybqrU+Y6PwiCKhblGbwVqbvapD2
        A1hjEu4EtL6mm3v7hcgsO3Df33/ShRua6GW9/JQVDLfdznLfuTg8w5Ug+dysJfbr
        mB1G7nbqDYEyXQXNRWpQsLHYSD/ihaSKWNnOuV0c7ieJEzQAp++O+d3WUQIDAQAB
        AoGAA+J7dnBYWv4JPyth9ayNNLLcBmoUUIdwwNgow7orsM8YKdXzJSkjCT/dRarR
        eIDMaulmcQiils2IjSEM7ytw4vEOPWY0AVj2RPhD83GcYyw9sUcTaz22R5UgsQ8X
        7ikqBX+YO+diVBf2EqAoEihdO8App6jtlsQGsUjjlrKQIMECQQDSphyRLixymft9
        bip7N6YZA5RoiO1yJhPn6X2EQ0QxX8IwKlV654jhDcLsPBUJsbxYK0bWfORZLi8V
        +ambjnbxAkEA7pNmEvw/V+zw3DDGizeyRbhYgeZxAgKwXd8Vxd6pFl4iQRmvu0is
        d94jZzryBycP6HSRKN11stnDJN++5TEVYQJALfTjoqDqPY5umazhQ8SeTjLDvBKz
        iwXXre743VQ3mnYDzbJOt+OvrznrXtK03EqUhr/aUo0o3HQA/dBcOn3YYQJBAM98
        yAh48wogGnYVwYbwgI3cPrVy2hO6jPKHAyOce4flhHsDwO7rzHtPaZDtFfMciNxN
        DLXyrNtIQkx+f0JLBuECQCUfuJGL+qbExpD3tScBJPAIJ8ZVRVbTcL3eHC9q6gx3
        7Fmn9KfbQrUHPwwdo5nuK+oVVYnFkyKGPSer7ras8ro=
        -----END RSA PRIVATE KEY-----
        `)
        let pk = RsaPublicKey.fromPem(`
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDET7fvLupUBUc6ImwJejColybq
        rU+Y6PwiCKhblGbwVqbvapD2A1hjEu4EtL6mm3v7hcgsO3Df33/ShRua6GW9/JQV
        DLfdznLfuTg8w5Ug+dysJfbrmB1G7nbqDYEyXQXNRWpQsLHYSD/ihaSKWNnOuV0c
        7ieJEzQAp++O+d3WUQIDAQAB
        -----END PUBLIC KEY-----
        `)

        let text = 'moky'
        let textData = Buffer.from(text, 'utf-8')
        console.log('textData hex ' + textData.toString('hex'))
        let encrypted = pk.encrypt(textData)
        console.log('encrypted ' + encrypted.toString('base64'))
        let decrypted = sk.decrypt(encrypted)
        console.log('decrypted ' + decrypted)
        expect(decrypted.toString('utf-8')).toBe(text)

        let decrypted2 = sk.decrypt(Buffer.from('b7pdkzIZMhcZs6mK06aCEhQdYP9yY1vqJ521DyTD5oWS2ac5f7L9QkqXVvYUylrOlgf151M4FaYLEkuSTw1UgqBixMjLlXfacaH3MltYMzeQxcocY7QjUweUkprlw/2YraWJbdp68l3r+VqnZIcohoeXiYnsuMyY8RFfEh1WcSU=', 'base64'))
        console.log('decrypted2 ' + decrypted2)
        expect(decrypted2.toString('utf-8')).toBe(text)
    })


    test('RSA import sign', () => {
        let sk = RsaPrivateKey.fromPem(`
            -----BEGIN RSA PRIVATE KEY-----
            MIICXQIBAAKBgQC0DnIMYYVdF4hxCymHRufO07qdutakN2oQBj7on2b8R106vhoL
            pRMl4qL8K1Y6c+6yl5/teh4LKSx6aeWoL9FrEp+pNjJ0BpOURV7opWxa/wtaxF9l
            +7l5VFwzKbK4ihZ3aAdZc/T9xPBZDOcnBvOIXo3Bwfkecsw2uCmxnjnNLQIDAQAB
            AoGADi5wFaENsbgTh0HHjs/LHKto8JjhZHQ33pS7WjOJ1zdgtKp53y5sfGimCSH5
            q+drJrZSApCCcsMWrXqPO8iuX/QPak72yzTuq9MEn4tusO/5w8/g/csq+RUhlLHL
            dOrPfVciMBXgouT8BB6UMa0e/g8K/7JBV8v1v59ZUccSSwkCQQD67yI6uSlgy1/N
            WqMENpGc9tDDoZPR2zjfrXquJaUcih2dDzEbhbzHxjoScGaVcTOx/Aiu00dAutoN
            +Jpovpq1AkEAt7EBRCarVdo4YKKNnW3cZQ7u0taPgvc/eJrXaWES9+MpC/NZLnQN
            F/NZlU9/H2607/d+Xaac6wtxkIQ7O61bmQJBAOUTMThSmIeYoZiiSXcrKbsVRneR
            JZTKgB0SDZC1JQnsvCQJHld1u2TUfWcf3UZH1V2CK5sNnVpmOXHPpYZBmpECQBp1
            hJkseMGFDVneEEf86yIjZIM6JLHYq2vT4fNr6C+MqPzvsIjgboJkqyK2sLj2WVm3
            bJxQw4mXvGP0qBOQhQECQQCOepIyFl/a/KmjVZ5dvmU2lcHXkqrvjcAbpyO1Dw6p
            2OFCBTTQf3QRmCoys5/dyBGLDhRzV5Obtg6Fll/caLXs
            -----END RSA PRIVATE KEY-----
            `)
        let pk = RsaPublicKey.fromPem(`
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0DnIMYYVdF4hxCymHRufO07qd
            utakN2oQBj7on2b8R106vhoLpRMl4qL8K1Y6c+6yl5/teh4LKSx6aeWoL9FrEp+p
            NjJ0BpOURV7opWxa/wtaxF9l+7l5VFwzKbK4ihZ3aAdZc/T9xPBZDOcnBvOIXo3B
            wfkecsw2uCmxnjnNLQIDAQAB
            -----END PUBLIC KEY-----
            `)

        // from python client
        let signature = 'c1AoopaU7L+gaTvz4YwpFuWefSqo9qkzcLY3YFVa9yM18XkuRAA2GVVwhKJ44CFYRbPIDoROvZFUR+QKqdS4yDAE6gQvWoVK3LrAyUjAZOuyVFjFfOJsvGnHeASqHBVOqy8Ll2Igh86Kip8XOm2HbHvelQsJgecBIEElQWkx8Tw='
        let data= 'i1xSn1KflQg/IwFNP4GvefwVQgYrUFjxtn/dRfnokh8MDgrW1Uh3/g7H2mPNecKb'
        expect(pk.verify(Buffer.from(data, 'base64'), Buffer.from(signature, 'base64'))).toBe(true)
    })

    test('RSA2', () => {
        let sk = RsaPrivateKey.fromPem(`
        -----BEGIN RSA PRIVATE KEY-----
        MIICXQIBAAKBgQC0DnIMYYVdF4hxCymHRufO07qdutakN2oQBj7on2b8R106vhoL
        pRMl4qL8K1Y6c+6yl5/teh4LKSx6aeWoL9FrEp+pNjJ0BpOURV7opWxa/wtaxF9l
        +7l5VFwzKbK4ihZ3aAdZc/T9xPBZDOcnBvOIXo3Bwfkecsw2uCmxnjnNLQIDAQAB
        AoGADi5wFaENsbgTh0HHjs/LHKto8JjhZHQ33pS7WjOJ1zdgtKp53y5sfGimCSH5
        q+drJrZSApCCcsMWrXqPO8iuX/QPak72yzTuq9MEn4tusO/5w8/g/csq+RUhlLHL
        dOrPfVciMBXgouT8BB6UMa0e/g8K/7JBV8v1v59ZUccSSwkCQQD67yI6uSlgy1/N
        WqMENpGc9tDDoZPR2zjfrXquJaUcih2dDzEbhbzHxjoScGaVcTOx/Aiu00dAutoN
        +Jpovpq1AkEAt7EBRCarVdo4YKKNnW3cZQ7u0taPgvc/eJrXaWES9+MpC/NZLnQN
        F/NZlU9/H2607/d+Xaac6wtxkIQ7O61bmQJBAOUTMThSmIeYoZiiSXcrKbsVRneR
        JZTKgB0SDZC1JQnsvCQJHld1u2TUfWcf3UZH1V2CK5sNnVpmOXHPpYZBmpECQBp1
        hJkseMGFDVneEEf86yIjZIM6JLHYq2vT4fNr6C+MqPzvsIjgboJkqyK2sLj2WVm3
        bJxQw4mXvGP0qBOQhQECQQCOepIyFl/a/KmjVZ5dvmU2lcHXkqrvjcAbpyO1Dw6p
        2OFCBTTQf3QRmCoys5/dyBGLDhRzV5Obtg6Fll/caLXs
        -----END RSA PRIVATE KEY-----
        `)
        let pk = RsaPublicKey.fromPem(`
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0DnIMYYVdF4hxCymHRufO07qd
        utakN2oQBj7on2b8R106vhoLpRMl4qL8K1Y6c+6yl5/teh4LKSx6aeWoL9FrEp+p
        NjJ0BpOURV7opWxa/wtaxF9l+7l5VFwzKbK4ihZ3aAdZc/T9xPBZDOcnBvOIXo3B
        wfkecsw2uCmxnjnNLQIDAQAB
        -----END PUBLIC KEY-----
        `)
        // let pk = sk.toPublicKey();

        let text = 'moky'
        let textData = Buffer.from(text, 'utf-8')
        let signature = sk.sign(textData).toString('base64')
        console.log('RSA2 text ' + Buffer.from(text, 'utf-8').toString('base64'))
        console.log('RSA2 signature ' + signature)
        // Buffer.from(`HM+YPstp0fpWV06DMze9UmLbo9XpQkUUQL6gS9KPDozdNOY597Beew9+mB42mtqFjCXbWfe2H7wfaO0mf6ufEXZBvLwHGgsGmC4Ticw4STeq0nvwr3okLfFKEOJNup9T4luQ0t5KepljkNgzd8yia5Ru01tHCjRXrSYGSP8YCxg=`, 'base64')
        expect(pk.verify(textData, Buffer.from(signature, 'base64'))).toBe(true)
    })

    test('RsaPrivateKey', () => {
        let sk = RsaPrivateKey.fromPem('-----BEGIN PRIVATE KEY-----' +
            'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANESTe7LjH2LhrXo' +
            '5g5gSnkivZ/XqWyZQcHYeMYOXGRTSO71gCnJ5mVRdvX3VmTEna/Hb68qmk3iAosP' +
            'LmvskxOnByHUI29x7JJfoOIziXBMCdQRmIFiA0E2sog0S0mZdZJkFN5Hu/scf8TE' +
            '0/m/KGGTTovWU6iSeFhyr30WNMaHAgMBAAECgYAE609WHQfzNEM5KH+xOubFruGT' +
            'Tzm3SmvXqcY9srzNx3/hz3jygsOfAqmv49/ugwnKxwCDuJbk2jqBFxxagbh8JPmM' +
            'G8nNwyWhmcDfqwTRu3OVOP//vXigFiIRw7hpYLskHIyBVZnZZqSotAaiK/igp3OL' +
            'OBzQuYILdczn4X5GkQJBAPjIdAm4l3r+OBcgTy/zcCJQkOHQ3yc63ZIapbNmlgoz' +
            'U5RAhX6yzdKRHPnJap9QEqDJTw5WRFaPvxG5mLZayKMCQQDXIvCj6muQGbmuBtAg' +
            'ZGcMnkFt//T+n59Il+ba2JDWj3hOO6Emzj16EUu0kqlBP3fGU6cXAjusAlZVR0s9' +
            'SzTNAkAvjqIf+Zl7eX1fbl203ORiquQHRtZhuW8BrvZeBQ5JhOZFQNBEGAogZn0T' +
            'gt1O9w+YjOL/6p3FrlToHoKC2XfhAkEAipTPPkd7Ek//88Ifvz3tw4sNyrXeM0bP' +
            'bAutgbuPUScJ8BspK74ei8soYSE4NfeUSAUK1R9zINJAmp5aMRmI4QJBAL29qAbT' +
            '53Eua+VeDqxgQ3Vz54jwokhqkqDRcHM8Cphx9PZyEXd1Q8DehN+uTnUxsdoaMjVS' +
            'R3vpWnZDzckKVuk=' +
            '-----END PRIVATE KEY-----')
        expect(sk).not.toBeNull()

        sk = RsaPrivateKey.fromPem('-----BEGIN RSA PRIVATE KEY-----' +
            'MIICXAIBAAKBgQC5BW6T9GVaaG/epGDjPpY3wN0DrBt+NojvxkEgpUdOAxgAepqe' +
            'GbSqtXAd+MOOBbHxIOEwrFC9stkypQgxrB49tXDI+4Jj8MuKI15HEmI8k7+tRDOl' +
            'J5TFSL2J9KA3GuQbyVAhlpxl+YnV7yjxP9l1dkbApg1ixSd5KOPbaQ00WQIDAQAB' +
            'AoGAYiqzpOTC8dj/og1tKqUGZsZ5fX1PiQO+XBnAbGXFE2sozPhAGSpiZUCnH//h' +
            'IfV7mAht8rk6java+bf+RPyhfg0zW7oXy0pm8DwoW7+0fOzQ4sEYeoqza/VrkYwR' +
            '5BxBa+KyT1HCi4uXogyDlQT1p0ZT0iaqZBfTApdyVkmcQEECQQDhfPl+ILl0bh0H' +
            '8ORoMmmxAZMn293+de441OlAjL3CsF4yhUUdavAYWM0RAV5MJtKUTR4ZpRXkB/pq' +
            'kgyTxpr9AkEA0g6pQRpcGxulr2758ZlOLdL8B1n1ubre464IKQ0zNfERKhR/j7U8' +
            'LGF+3mhZuoSEdklwLCJ8ZMvIhkV0v8JjjQJBANtqXOyas1vUenNruRabV7ViLuuu' +
            'S0p9Px4WMBMb4Ns9+6t1e1ew44kNgB54EmZPsMGWeR/DQJXwHYDuNUbnD5ECQA7S' +
            'Gf8N7RG8kaQfIGN7fZieGkoqfrvsA23tCYZb+BEGQT/G0nlBQE2hU2I92pbeYro1' +
            '1ERI6p3yAuP2YpZlEMECQGNzhqshYfDiWwU4Q3aZWkRrv74uIXk1HQoFH1BthzQJ' +
            'TbzKH/LEqZN8WVau3bf41yAx2YoaOsIJJtOUTYcfh14=' +
            '-----END RSA PRIVATE KEY-----')
        expect(sk).not.toBeNull()
    })

    test('RsaPublicKey', () => {
        let pk = RsaPublicKey.fromPem('-----BEGIN PUBLIC KEY-----' +
            'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaLj4hou1yDaa+c3EYT5iOPI4O' +
            'ks0aGXL8PLyaMZ6S62RmT6bOxNh6Q5fl0SozzheSMBkDaQl+y8Zeia+OW12T9dkg' +
            'VKOYBIrJ6rqWPqNVj2GAWOybUtZSyDcFgeuKpD3/QX2xLcWOfzrg0aYCkYNQUyAv' +
            'hr9I6B91DROWYQ9cEwIDAQAB' +
            '-----END PUBLIC KEY-----')
        expect(pk).not.toBeNull()
    })

    test('AES', () => {
        let key = AesSymmKey.create()
        let data = Buffer.from('0102030405', 'hex')
        let encData = key.encrypt(data)
        expect(encData).not.toBeNull()

        let originData = key.decrypt(encData)
        expect(data.equals(originData)).toBe(true)
    })
})