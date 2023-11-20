import { v4 } from "uuid";
import EncryptionManager, { getEncryptionKey } from '../src/encryption'


const keyGroup = [v4(), v4(), v4()]
const pepperArray = [v4(), v4(), v4()]
describe('Encryption key functions', () => {
    it('getEncryptionKey', () => {
        for (let i = 0; i < 10; i++) {
            //@ts-ignore
            const valueA = i % 5
            //@ts-ignore
            const valueB = i % 5 + 5

            const initialKeyA1 = getEncryptionKey(keyGroup, i, valueA)
            const initialKeyA2 = getEncryptionKey(keyGroup, 20, valueB)
            expect(initialKeyA1).not.toBe(initialKeyA2)
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
        const encrypt = encryptionClass.singleEncryption(inputText, key, opt)
        const decrypt = encryptionClass.singleDecrypt(encrypt, key, opt)
        expect(decrypt).toEqual(inputText)

    })
    it('Test symmetrical Encryption', () => {
        for (let i = 0; i < 20; i++) {
            const testString = randomString();
            const opt = v4()
            const encryptData = encryptionClass.encryptText(testString, i, pepperArray, i === 0 ? undefined : opt)
            const decryptValue1 = encryptionClass.decryptData(encryptData, i, pepperArray, i === 0 ? undefined : opt)
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
                testBool: !!(Math.round(Math.random())),
                testNaN: NaN
            };
            const opt = v4()
            const encryptData = encryptionClass.encryptText(JSON.stringify(testString), i, pepperArray, i === 0 ? undefined : opt)
            const decryptValue1 = encryptionClass.decryptData(encryptData, i, pepperArray, i === 0 ? undefined : opt)
            expect({ ...testString, testNaN: null }).toEqual(JSON.parse(decryptValue1))
        }
    })
    it('test encrypt Object', () => {
        for (let i = 0; i < 20; i++) {
            const testData = { testNum: 1, testBool: false, testString: v4() + v4() + v4() + ` $ @$% @#$% !#H | )(*&^%$#@!?><:"';{}[]) R46 46 3rh r 357 ryh r3y6 5346feh 3w45rfe aewrh `, testUndefined: undefined, testNull: null, }
            const opt = v4()
            const decryptData = encryptionClass.decryptObject(encryptionClass.encryptObjectData(testData, i, pepperArray, i === 0 ? undefined : opt), i, pepperArray, i === 0 ? undefined : opt)
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