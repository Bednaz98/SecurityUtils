import { v4 } from "uuid";
import { clearKeys, decryptData, decryptObject, defaultOptionString, encryptObjectData, encryptText, getEncryptionKey, getEncryptionKeyArray, getEncryptionPepper } from '../src/encryption'


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


    it("defaultOptionString", () => {
        const result = defaultOptionString()
        expect(typeof result === "string").toBeTruthy()
    })
    const undefinedKeys = "9a4b5bdf0f0c0abb07c0cceb97debe50a3a855849a4b5bdf0f0c0abb07c0cceb97debe50a3a85584050d9837e2d8faaa6adc770f22f815d00df13f97";
    it('getEncryptionKey, no valid keys', () => {
        const number: number = 8, varString: string = "desfhj"
        process.env.SERVER_PRIMARY_ENCRYPTION_A1 = undefined
        process.env.SERVER_PRIMARY_ENCRYPTION_A2 = undefined
        process.env.SERVER_PRIMARY_ENCRYPTION_B1 = undefined
        process.env.SERVER_PRIMARY_ENCRYPTION_B2 = undefined
        const resultKey = getEncryptionKey(number, true, varString)
        expect(resultKey).toBe(undefinedKeys)
    })
    const testA1 = "testA!", testA2 = "testA2", testB1 = "testB1", testB2 = "testB2"
    it('getEncryptionKey, valid keys', () => {
        const number: number = 8, varString: string = "desfhj";
        clearKeys();
        process.env.SERVER_ENCRYPTION_A1 = testA1
        process.env.SERVER_ENCRYPTION_A2 = testA2
        process.env.SERVER_ENCRYPTION_B1 = testB1
        process.env.SERVER_ENCRYPTION_B2 = testB2

        const resultKeyA = getEncryptionKey(number, true, varString)
        const newKey = "57931c74c0957de7c315390fd2347af9bb97916457931c74c0957de7c315390fd2347af9bb97916427ca4cc807f83621adb53b531bbad83910eaaa38";
        expect(resultKeyA).not.toBe(undefinedKeys)
        expect(resultKeyA).toBe(newKey)
        for (let i = 0; i < 20; i++) {
            expect(getEncryptionKey(i, true, v4())).not.toBe(newKey)
        }
    })
    it('getEncryptionKeyArray', () => {
        const AKeys = getEncryptionKeyArray(false)
        const BKeys = getEncryptionKeyArray(true)
        expect(AKeys).not.toEqual(BKeys);
        expect(AKeys?.length).toBeGreaterThan(0);
        expect(BKeys?.length).toBeGreaterThan(0);
        expect(AKeys.includes(testA1) && AKeys.includes(testA2)).toBeTruthy();
        expect(BKeys.includes(testB1) && BKeys.includes(testB2)).toBeTruthy();
    })
    it('getEncryptionPepper', () => {
        for (let i = 0; i < 20; i++) {
            const result = getEncryptionPepper(i)
            expect(result.length).toBe(1)
        }
    })
    it('Test symmetrical Encryption', () => {

        for (let i = 0; i < 20; i++) {
            const testString = v4() + v4() + v4() + " $ @$% @#$% !#H R46 46 3rh r 357 ryh r3y6 5346feh 3w45rfe aewrh ";
            const opt = v4()
            const encryptData = encryptText(testString, true, i === 0 ? undefined : opt)
            const decryptValue1 = decryptData(encryptData, true, i === 0 ? undefined : opt)
            expect(decryptValue1).toEqual(testString)
        }

    })
    it('test encrypt Object', () => {
        for (let i = 0; i < 20; i++) {
            const testData = { testNum: 1, testBool: false, testString: v4() + v4() + v4() + " $ @$% @#$% !#H R46 46 3rh r 357 ryh r3y6 5346feh 3w45rfe aewrh ", testUndefined: undefined, testNull: null, }
            const opt = v4()
            const decryptData = decryptObject(encryptObjectData(testData, true, i === 0 ? undefined : opt), true, i === 0 ? undefined : opt)
            expect(decryptData).toEqual(testData)
        }
    })

})