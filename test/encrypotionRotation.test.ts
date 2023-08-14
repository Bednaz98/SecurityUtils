import { decryptRotationText, encryptRotationText, resetKeys } from "../src/encryption";

describe('Encryption Rotation', () => {
    const OLD_ENV = process.env;
    const testA1 = "testA!", testA2 = "testA2", testB1 = "testB1", testB2 = "testB2", testC1 = "testC1", testC2 = "testC2"
    const DataString = 'TestingValue';
    let testString1 = '';
    let testString2 = '';
    beforeEach(() => {
        jest.resetModules()
        jest.clearAllMocks()
        process.env = { ...OLD_ENV };
        process.env.SERVER_ENCRYPTION_A1 = testA1;
        process.env.SERVER_ENCRYPTION_A2 = testA2;
        process.env.SERVER_ENCRYPTION_B1 = testB1;
        process.env.SERVER_ENCRYPTION_B2 = testB2;
        process.env.SERVER_ENCRYPTION_C1 = testC1;
        process.env.SERVER_ENCRYPTION_C2 = testC2;
        resetKeys();
        testString1 = encryptRotationText(DataString, false);
        testString2 = encryptRotationText(DataString, true);
    });
    afterAll(() => {
        process.env = OLD_ENV;
    });
    it("test rotation encryption initial", () => {
        testString1 = encryptRotationText(DataString, false);
        testString2 = encryptRotationText(DataString, true);
        expect(testString2).not.toBe(testString1)
        expect(decryptRotationText(testString1)).toBe(DataString)
        expect(decryptRotationText(testString2)).toBe(DataString)
    })
    it("test rotation encryption round 1", () => {
        process.env.SERVER_ENCRYPTION_A1 = testB1;
        process.env.SERVER_ENCRYPTION_A2 = testB2;
        process.env.SERVER_ENCRYPTION_B1 = testC1;
        process.env.SERVER_ENCRYPTION_B2 = testC2;
        resetKeys();
        expect(testString2).not.toBe(testString1)
        expect(decryptRotationText(testString1)).toBeUndefined()
        expect(decryptRotationText(testString2)).toBe(DataString)
    })
    it("test rotation encryption round 2", () => {
        process.env.SERVER_ENCRYPTION_A1 = testC1;
        process.env.SERVER_ENCRYPTION_A2 = testC2;
        process.env.SERVER_ENCRYPTION_B1 = testC1 + 1;
        process.env.SERVER_ENCRYPTION_B2 = testC2 + 2;
        resetKeys();
        expect(testString2).not.toBe(testString1)
        expect(decryptRotationText(testString1)).toBeUndefined()
        expect(decryptRotationText(testString2)).toBeUndefined()
    });

})