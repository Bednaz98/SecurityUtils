import hash from 'object-hash'
import bcrypt from 'bcrypt';
import { HashDataConfig, compareHash, getSaltRounds, hashData, insertHashPepper } from '../src/hash';
import { v4 } from 'uuid';

describe('Test Hash Functions', () => {
    const OLD_ENV = process.env;
    const pepperArray = ["test", "default", "other"];
    beforeEach(() => {
        jest.resetModules();
        jest.clearAllMocks();
        process.env = { ...OLD_ENV };
    });
    afterAll(() => {
        process.env = OLD_ENV;
    });
    it('test salt value', () => {
        process.env.SERVER_HASH_SALT_ROUNDS = undefined;
        const result1 = getSaltRounds();
        expect(result1).toBe(0);
        process.env.SERVER_HASH_SALT_ROUNDS = '5';
        const result2 = getSaltRounds();
        expect(result2).toBe(5);

    });
    it('insertPepper', () => {
        const hashString = "test", dataType = 8;
        const unPepperString = hash(hashString + hashString + dataType);
        const pepperString = insertHashPepper(hashString, dataType, pepperArray);
        expect(unPepperString).not.toBe(pepperString);
        expect(unPepperString.length === pepperString.length).toBeFalsy();
    });
    it('hashData', async () => {
        for (let i = 0; i < 10; i++) {
            const testHashData = { test: v4() };
            const index = 9;
            const testHash = hash(testHashData);
            const unPepperString = hash(testHash + testHash + index);
            const hashTest = await bcrypt.hash(unPepperString, getSaltRounds());
            const config: HashDataConfig = {
                dataType: index,
                pepperString: pepperArray
            };
            const checkHash = await hashData(testHashData, config);
            expect(hashTest === checkHash).toBeFalsy();
            expect(await compareHash(testHashData, hashTest, config)).toBeFalsy();
            expect(await compareHash(testHashData, checkHash, config)).toBeTruthy();
        };
    });
})