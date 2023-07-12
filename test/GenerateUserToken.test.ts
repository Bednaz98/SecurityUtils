import hash from 'object-hash'
import { decodeJWT, deleteNoneUniqueJWTProperties, generateJWT, getIssuer, getJWTIndex, getJWTKey, verifyJWT } from '../src/jwt/JwtGeneration'
import { JWTConfig } from '../src/jwt/types';

describe('Generate JWT Test', () => {
    const OLD_ENV = process.env;

    beforeEach(() => {
        jest.resetModules()
        jest.clearAllMocks()
        process.env = { ...OLD_ENV };
    });

    afterAll(() => {
        process.env = OLD_ENV;
    });

    it('getIssuer valid keys', () => {
        const test = "testing";
        process.env.SERVER_JWT_ISSUER = test;
        const result = getIssuer();
        expect(result).toBe(test);

    });
    it('getIssuer no keys', () => {
        process.env.SERVER_JWT_ISSUER = undefined;
        const result = getIssuer();
        expect(result).toBe('default');

    });

    it('getJWTKeys no key', () => {
        delete process.env.SERVER_JWT_KEY1
        delete process.env.SERVER_JWT_KEY2
        delete process.env.SERVER_JWT_KEY3
        // console.log(process.env)
        const index = 4
        const result1 = getJWTKey(index)
        expect(result1).toBe(hash('default'))

    })

    it('getJWTKey valid keys', () => {
        const key1 = 'test1', key2 = "346", key3 = 'wrayhuw';
        const Array = ["default", key1, key2, key3]
        process.env.SERVER_JWT_KEY1 = key1
        process.env.SERVER_JWT_KEY2 = key2
        process.env.SERVER_JWT_KEY3 = key3
        const index = 4
        const result1 = getJWTKey(index)
        expect(result1).toBe(hash(Array[index % Array.length]))
    });
    it("Test getJWTIndex", () => {
        const result1 = getJWTIndex(null)
        expect(result1).toBe(0)
        const result2 = getJWTIndex('dgjgde')
        expect(result2).toBe(0)
        const data = { test2: "test" }, config: JWTConfig = {
            expireTime: 10,
            subject: "afh",
        }
        const jwt = generateJWT(data, config)
        const result3 = getJWTIndex(jwt)
        expect(result3).toBe(1824)

    })

    it('Test decode and delete unique properties', () => {

        const subject1 = 'test1'
        const subject2 = 'test2'
        const test1 = "test"
        const test2 = 5
        const data1: any = {}, config1: JWTConfig = {
            expireTime: 10
        }
        const data2: any = { test2 }, config2: JWTConfig = {
            expireTime: 10,
            subject: subject1,
        }
        const data3: any = { test2, test1 }, config3: JWTConfig = {
            expireTime: 10,
            subject: subject2,
            audience: "sfhsf"
        }
        const jwt1 = generateJWT(data1, config1)
        const jwt2 = generateJWT(data2, config2)
        const jwt3 = generateJWT(data3, config3)

        const decodeResult1 = deleteNoneUniqueJWTProperties(decodeJWT<{}>(jwt1))
        const decodeResult2 = deleteNoneUniqueJWTProperties(decodeJWT<any>(jwt2))
        const decodeResult3 = deleteNoneUniqueJWTProperties(decodeJWT<any>(jwt3))
        expect(decodeResult1).toEqual(data1)
        expect(decodeResult2).toEqual(data2)
        expect(decodeResult3).toEqual(data3)

    })
    it('verifyJWT normal checks', () => {

        const data: any = { test2: "test" }, config: JWTConfig = {
            expireTime: 10,
            subject: "afh",
        }
        const jwt = generateJWT(data, config)
        const result1 = verifyJWT(jwt, undefined, data.subject)
        expect(result1).toBeTruthy()
        const result2 = verifyJWT('afhawf', undefined, data.subject)
        expect(result2).toBeFalsy()
    })

})