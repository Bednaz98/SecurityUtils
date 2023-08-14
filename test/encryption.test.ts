import { v4 } from "uuid";
import { resetKeys, decryptData, decryptObject, decryptRotationText, defaultOptionString, encryptObjectData, encryptRotationText, encryptText, getEncryptionKey, getEncryptionKeyArray, getEncryptionPepper, rotateEncryptionDataAB, getEncryptionCheckString } from '../src/encryption'
import hash from 'object-hash';


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
        const number = 8, varString = "desfhj"
        const resultKey = getEncryptionKey(number, true, varString)
        expect(resultKey).toBe(undefinedKeys)
    })
    it("", () => {

    });
    const testA1 = "testA!", testA2 = "testA2", testB1 = "testB1", testB2 = "testB2", testC1 = "testC1", testC2 = "testC2"
    it('getEncryptionKey, valid keys', () => {
        const number = 8, varString = "desfhj";
        process.env.SERVER_ENCRYPTION_A1 = testA1;
        process.env.SERVER_ENCRYPTION_A2 = testA2;
        process.env.SERVER_ENCRYPTION_B1 = testB1;
        process.env.SERVER_ENCRYPTION_B2 = testB2;
        process.env.SERVER_ENCRYPTION_C1 = testC1;
        process.env.SERVER_ENCRYPTION_C2 = testC2;
        resetKeys();

        const resultKeyA = getEncryptionKey(number, true, varString)
        const newKey = "57931c74c0957de7c315390fd2347af9bb97916457931c74c0957de7c315390fd2347af9bb97916427ca4cc807f83621adb53b531bbad83910eaaa38";
        expect(resultKeyA).not.toBe(undefinedKeys)
        expect(resultKeyA).toBe(newKey)
        for (let i = 0; i < 20; i++) {
            expect(getEncryptionKey(i, true, v4())).not.toBe(newKey)
        }
    })
    it('getEncryptionKeyArray', () => {
        const AKeys = getEncryptionKeyArray(false);
        const BKeys = getEncryptionKeyArray(true);
        const CKeys = getEncryptionKeyArray(2);
        expect(AKeys).not.toEqual(BKeys);
        expect(CKeys).not.toEqual(BKeys);
        expect(CKeys).not.toEqual(AKeys);
        expect(AKeys?.length).toBeGreaterThan(0);
        expect(BKeys?.length).toBeGreaterThan(0);
        expect(CKeys?.length).toBeGreaterThan(0);
        expect(AKeys.includes(testA1) && AKeys.includes(testA2)).toBeTruthy();
        expect(BKeys.includes(testB1) && BKeys.includes(testB2)).toBeTruthy();
        expect(CKeys.includes(testC1) && CKeys.includes(testC2)).toBeTruthy();
    })
    it('getEncryptionPepper', () => {
        for (let i = 0; i < 20; i++) {
            const result = getEncryptionPepper(i)
            expect(result.length).toBe(1)
        }
    })
    it('Test symmetrical Encryption', () => {
        for (let i = 0; i < 20; i++) {
            const testString = v4() + v4() + v4() + `!@#$%^&*()_+=-09876543321~|{}[];:?/><,. $ @$% @#$% !#H R46 46 3rh r 357 ryh r3y6 5346feh 3w45rfe aewrh `;
            const opt = v4()
            const encryptData = encryptText(testString, true, i === 0 ? undefined : opt)
            const decryptValue1 = decryptData(encryptData, true, i === 0 ? undefined : opt)
            expect(decryptValue1).toEqual(testString)
        }
    })
    it('test encrypt Object', () => {
        for (let i = 0; i < 20; i++) {
            const testData = { testNum: 1, testBool: false, testString: v4() + v4() + v4() + ` $ @$% @#$% !#H | )(*&^%$#@!?><:"';{}[]) R46 46 3rh r 357 ryh r3y6 5346feh 3w45rfe aewrh `, testUndefined: undefined, testNull: null, }
            const opt = v4()
            const decryptData = decryptObject(encryptObjectData(testData, true, i === 0 ? undefined : opt), true, i === 0 ? undefined : opt)
            expect(decryptData).toEqual(testData)
        }
    })
    it("rotateEncryptionDataAB", () => {
        const testData = 'testing';
        const initEncrypt = encryptText(testData, 0)
        const rotation = rotateEncryptionDataAB(initEncrypt, false) ?? ''
        expect(initEncrypt).not.toBe(rotation)
        expect(decryptData(rotation, 1)).toBe(testData)
    })
    it("rotateEncryptionDataBC", () => {
        const testData = 'testing';
        const initEncrypt = encryptText(testData, 1)
        const rotation = rotateEncryptionDataAB(initEncrypt, true) ?? ''
        expect(initEncrypt).not.toBe(rotation)
        expect(decryptData(rotation, 2)).toBe(testData)
    })
    it("rotateEncryptionData failed", () => {
        const testData = 'testing';
        const initEncrypt = encryptText(testData, 2)
        const rotation = rotateEncryptionDataAB(initEncrypt, true)
        expect(initEncrypt).not.toBe(rotation)
        expect(rotation).toBeNull();
    })

    it('getEncryptionCheckString undefine', () => {
        const value = getEncryptionCheckString()
        expect(value).toBe(hash('|$$%12345|>'));
    });

})