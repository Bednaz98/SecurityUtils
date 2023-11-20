

import { v4 } from 'uuid'
import { getPepper, getInsertIndex, insertPepper, removePepper, hashAPIKey, } from '../src/common/security-Utilties';



describe('Security Utilities', () => {
    const OLD_ENV = process.env;
    beforeEach(() => {
        jest.resetModules()
        jest.clearAllMocks()
        process.env = { ...OLD_ENV };
    });
    afterAll(() => {
        process.env = OLD_ENV;
    });
    const pepperArray = ["test", "default", "other"]

    it('getPepper', () => {
        const pepper = getPepper(0, pepperArray);
        expect(pepper).toBe("6");
    })
    it('getInsertIndex', () => {

        for (let i = 0; i < 20; i++) {
            const test = v4()
            const value = getInsertIndex(test, `${i}`, 0)
            expect(value).toBeGreaterThan(0)
            expect(value).toBeLessThan(test.length + 1)
        }

    })
    it('insertPepper', () => {
        // make sure no data was lost
        for (let i = 0; i < 20; i++) {
            const testString = v4()
            const pepperArray = ["!", "@", "$", "*", "(", ")", "&"]
            const testPepper = pepperArray[i % pepperArray.length]
            const check = insertPepper(testString, testPepper, `${i}`)
            // make sure exactly 1 extra character was added
            expect(check.length).toBe(testString.length + 1)
            // make sure pepper is present
            expect(check.includes(testPepper))
            // make sure no data was dropped
            expect(check.replace(testPepper, "") === testString).toBeTruthy()
            // make sure the 0 index is not a pepper
            expect(check[0]).not.toBe(testPepper);
        }
    })
    it('Remove Pepper', () => {

        for (let i = 0; i < 20; i++) {
            const testString = v4()
            const pepper = getPepper(i, pepperArray)
            const pepperString = insertPepper(testString, pepper, `${i}`)
            const recoverString = removePepper(pepperString, pepper, `${i}`)
            expect(recoverString).toBe(testString)
        }

    })
    it('hashAPIKey', () => {
        const test: string[] = []
        for (let i = 0; i < 50; i++) {
            const result = hashAPIKey(pepperArray, i)
            expect(typeof result === "string").toBeTruthy()
            expect(test.includes(result)).toBeFalsy()
            test.push(result)
        }
    })
})