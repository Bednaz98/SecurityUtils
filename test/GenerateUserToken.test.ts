import { JWTManagerConfig, deleteNoneUniqueJWTProperties } from '../src/jwt'
import { v4 } from 'uuid';
import { JWTManager } from '../src/jwt/jwtClass';

describe('Generate JWT Test', () => {
    const key1 = v4()
    const key2 = v4()
    const key3 = v4()
    const config: JWTManagerConfig = {
        getJWTKey: () => [key1, key2, key3],
        issuer: 'test'
    }
    const jWTManager = new JWTManager(config)
    const userID = "testUsert"

    it('Test decode and delete unique properties', () => {

        const subject1 = 'test1'
        const subject2 = 'test2'
        const test1 = "test"
        const test2 = 5
        const data1: any = {
            expireTime: 10
        }
        const data2: any = {
            test2,
            expireTime: 10,
            subject: subject1,
        }
        const data3: any = {
            test2, test1,
            expireTime: 10,
            subject: subject2,
            audience: "sfhsf"
        }
        const jwt1 = jWTManager.generateJWT(data1)
        const jwt2 = jWTManager.generateJWT(data2)
        const jwt3 = jWTManager.generateJWT(data3)

        const decodeResult1 = deleteNoneUniqueJWTProperties(jWTManager.decodeJWT<{}>(jwt1))
        const decodeResult2 = deleteNoneUniqueJWTProperties(jWTManager.decodeJWT<any>(jwt2))
        const decodeResult3 = deleteNoneUniqueJWTProperties(jWTManager.decodeJWT<any>(jwt3))
        expect(decodeResult1).toEqual(data1)
        expect(decodeResult2).toEqual(data2)
        expect(decodeResult3).toEqual(data3)

    })
    it('verifyJWT normal checks', () => {

        const data: any = {
            test2: "test",
            expireTime: 10,
            subject: undefined,
            audience: "test"
        }
        const jwt = jWTManager.generateJWT(data)
        const result1 = jWTManager.verifyJWT(jwt, data.audience, data.subject)
        expect(result1).toBeTruthy()
        const result2 = jWTManager.verifyJWT('afhawf', undefined, data.subject)
        expect(result2).toBeFalsy()
    })
    it(' verify access JWT normal checks', () => {
        const data: any = {
            test2: "test",
            expireTime: 10,
            subject: "testing",
            audience: "testing"
        }
        const jwt = jWTManager.generateAccessToken("testUser", data, data.audience)
        const result1 = jWTManager.verifyJWT(jwt, data.audience, data.subject)
        expect(result1).toBeTruthy()
        const jwt2 = jWTManager.generateAccessToken("testUser", undefined, data.audience)
        const result2 = jWTManager.verifyJWT(jwt2, undefined, "notValid")
        expect(result2).toBeFalsy()
    })
    it(' verify refresh JWT normal checks', () => {
        const data: any = {
            test2: "test",
            expireTime: 10,
            subject: "testing",
            audience: "testing"
        }
        const jwt = jWTManager.generateRefreshToken("testUser", data, data.audience)
        const result1 = jWTManager.verifyJWT(jwt, data.audience, data.subject)
        expect(result1).toBeTruthy()
        const jwt2 = jWTManager.generateRefreshToken("testUser", undefined, data.audience)
        const result2 = jWTManager.verifyJWT(jwt2, undefined, "notValid")
        expect(result2).toBeFalsy()
    })

})