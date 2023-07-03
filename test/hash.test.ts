import hash from 'object-hash'
import bcrypt from 'bcrypt';
import { compareHash, getSaltRounds, hashData, insertPepper } from '../src/hash'

describe('Test Hash Functions', () => {
    const OLD_ENV = process.env;

    beforeEach(() => {
        jest.resetModules()
        jest.clearAllMocks()
        process.env = { ...OLD_ENV };
    });

    afterAll(() => {
        process.env = OLD_ENV;
    });

    it('test salt value', () => {
        process.env.SERVER_HASH_SALT_ROUNDS = undefined
        const result1 = getSaltRounds()
        expect(result1).toBe(0)
        process.env.SERVER_HASH_SALT_ROUNDS = '5'
        const result2 = getSaltRounds()
        expect(result2).toBe(5)

    })
    it('insertPepper', () => {
        const hashString: string = "test", dataType: number = 8;
        const unPepperString = hash(hashString + hashString + dataType);
        const pepperString = insertPepper(hashString, dataType);
        expect(unPepperString).not.toBe(pepperString);
        expect(unPepperString.length === pepperString.length).toBeFalsy();
    })
    it('hashData', async () => {
        const testHashData = { test: "test" };
        const index = 9;
        const testHash = hash(testHashData);
        const unPepperString = hash(testHash + testHash + index);
        const hashTest = await bcrypt.hash(unPepperString, getSaltRounds());
        const checkHash = await hashData(testHashData, index);
        expect(hashTest === checkHash).toBeFalsy();
        expect(await compareHash(testHashData, index, hashTest)).toBeFalsy();
        expect(await compareHash(testHashData, index, checkHash)).toBeTruthy();

    })
})