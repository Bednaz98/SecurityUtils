import bcrypt from 'bcrypt';
import hash from 'object-hash'
import { getPepper, getPepperString } from '../common/security-Utilties';
import { convertStringToNumber } from '../common/utilities';
/** INTERNAL FUNCTION DO NOT USE DIRECTLY, gets the number of routes to salt a value*/
export function getSaltRounds(): number {
    return Number(process.env.SERVER_HASH_SALT_ROUNDS ?? 0);
};


/** INTERNAL FUNCTION DO NOT USE DIRECTLY, inserts pepper into a given string*/
export function insertHashPepper(insertString: string, dataType: number): string {
    const stringArray2 = hash(insertString + dataType)
    const insertValue2 = convertStringToNumber(stringArray2)
    const pepperIndex = insertValue2 + dataType;
    const pepperStringIndex = getPepperString().split('').map((e) => e.charCodeAt(0)).reduce((a, b) => a + b)
    const pepper = getPepper(pepperIndex + pepperStringIndex);
    const stringArray = hash(insertString + insertString + dataType)
    const insertValue = convertStringToNumber(stringArray)
    const insertNumber = (insertValue + pepperStringIndex) % stringArray.length
    const newString = [...stringArray.slice(0, insertNumber), pepper, ...stringArray.slice(insertNumber)]
    return newString.join('');
}

/** this function hash any arbitrary JavaScript object, adds a pepper and then hashes the data again with a salt.
 * @dataType this is used to provide variability when hashing data
*/
export async function hashData(inputData: any, dataType: number): Promise<string> {
    const tempData = insertHashPepper(hash(inputData), dataType)
    return await bcrypt.hash(tempData, getSaltRounds());
}

/** used to verify if the hash string is derived from the input data */
export async function compareHash(inputData: any, dataType: number, hashString: string): Promise<boolean> {
    const tempData = insertHashPepper(hash(inputData), dataType)
    return await bcrypt.compare(tempData, hashString);
}




