import { v4 } from "uuid";
import EncryptionManager, { decryptData, decryptObject, defaultOptionString, encryptObjectData, encryptText, getEncryptionKey, getEncryptionKeyArray, getEncryptionPepper, NEncryption, NDecryption, singleEncryption, singleDecrypt } from '../src/encryption'
import { keyGroups } from "../src/common/types";

const keyGroup: keyGroups = {
    0: [v4(), v4(), v4()],
    1: [v4(), v4(), v4()],
    2: [v4(), v4(), v4()],
    3: [v4(), v4(), v4()],
    4: [v4(), v4(), v4()]
}
describe('Encryption key functions', () => {
    it('getEncryptionKey', () => {

        for (let i = 0; i < 10; i++) {
            //@ts-ignore
            const valueA: 0 | 1 | 2 = (i % 3)
            //@ts-ignore
            const valueB: 0 | 1 | 2 = (i + 2 % 3)
            const rand = v4()
            const initialKeyA1 = getEncryptionKey(keyGroup, i, valueA, rand)
            const initialKeyA2 = getEncryptionKey(keyGroup, 20, valueB, rand)
            expect(initialKeyA1).not.toBe(initialKeyA2)
        }


    })
    it("defaultOptionString", () => {
        const result = defaultOptionString()
        expect(typeof result === "string").toBeTruthy()
    })
    it('getEncryptionPepper', () => {
        for (let i = 0; i < 20; i++) {
            const result = getEncryptionPepper(i)
            expect(result.length).toBe(1)
        }
    })
})

describe('encryption test', () => {
    const OLD_ENV = process.env;
    beforeEach(() => {
        jest.resetModules()
        jest.clearAllMocks()
        process.env = { ...OLD_ENV };
    });
    afterAll(() => {
        process.env = OLD_ENV;
    });

    const encryptionClass = new EncryptionManager(() => keyGroup)


    const randomString = () => v4() + v4() + v4() + `${Math.random()}` + `!@#$%^&*()_+=-09876543321~|{}[];:?/><,. \n$ @$% @#$% !#H R46 46 3rh r 357 \tryh r3y6 5346feh 3w45rfe aewrh `
    it("Test Single Encryption", () => {
        const inputText = randomString();
        const key = 0
        const opt = undefined
        const varNum = 0
        const encrypt = encryptionClass.singleEncryption(inputText, varNum, key, opt)
        const decrypt = encryptionClass.singleDecrypt(encrypt, varNum, key, opt)
        expect(decrypt).toEqual(inputText)

    })
    it('Test symmetrical Encryption', () => {
        for (let i = 0; i < 20; i++) {
            const testString = randomString();
            const opt = v4()
            const encryptData = encryptionClass.encryptText(testString, i, i === 0 ? undefined : opt)
            const decryptValue1 = encryptionClass.decryptData(encryptData, i, i === 0 ? undefined : opt)
            expect(decryptValue1).toEqual(testString)
        }
    })
    it('Test symmetrical Encryption JSON String', () => {
        for (let i = 0; i < 20; i++) {
            const testString = {
                testString: v4(),
                0: true,
                2: 2,
                testNum: 3,
                testBool: !!(Math.round(Math.random()))
            };
            const opt = v4()
            const encryptData = encryptionClass.encryptText(JSON.stringify(testString), i, i === 0 ? undefined : opt)
            const decryptValue1 = encryptionClass.decryptData(encryptData, i, i === 0 ? undefined : opt)
            expect(testString).toEqual(JSON.parse(decryptValue1))
        }
    })
    it('test encrypt Object', () => {
        for (let i = 0; i < 20; i++) {
            const testData = { testNum: 1, testBool: false, testString: v4() + v4() + v4() + ` $ @$% @#$% !#H | )(*&^%$#@!?><:"';{}[]) R46 46 3rh r 357 ryh r3y6 5346feh 3w45rfe aewrh `, testUndefined: undefined, testNull: null, }
            const opt = v4()
            const decryptData = encryptionClass.decryptObject(encryptionClass.encryptObjectData(testData, i, i === 0 ? undefined : opt), i, i === 0 ? undefined : opt)
            expect(decryptData).toEqual(testData)
        }
    })

    it("Test N Encryption", () => {
        for (let i = 0; i < 20; i++) {
            const inputText = randomString();
            const opt = i ? `${i}` : undefined
            const encrypt = encryptionClass.NEncryption(inputText, i, opt)
            const decrypt = encryptionClass.NDecryption(encrypt, i, opt)
            expect(decrypt).toEqual(inputText)

        }

    })

})