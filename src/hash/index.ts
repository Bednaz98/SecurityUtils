import bcrypt from 'bcrypt';
import hash from 'object-hash'
import { getPepper } from '../common/security-Utilties';
import { convertStringToNumber } from '@jabz/math-js';

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, gets the number of routes to salt a value*/
export function getSaltRounds(): number {
    return Number(process.env.SERVER_HASH_SALT_ROUNDS ?? 0);
};


/** INTERNAL FUNCTION DO NOT USE DIRECTLY, inserts pepper into a given string*/
export function insertHashPepper(insertString: string, dataType: number, pepperString: string[]): string {
    const stringArray2 = hash(insertString + dataType)
    const insertValue2 = convertStringToNumber(stringArray2)
    const pepperIndex = insertValue2 + dataType;
    const pepper = getPepper(pepperIndex + pepperString.length, pepperString);
    const stringArray = hash(insertString + insertString + dataType)
    const insertValue = convertStringToNumber(stringArray)
    const insertNumber = (insertValue + pepperString.length) % stringArray.length
    const newString = [...stringArray.slice(0, insertNumber), pepper, ...stringArray.slice(insertNumber)]
    return newString.join('');
}


export interface HashDataConfig {
    dataType: number,
    pepperString: string[]
}

/** this function hash any arbitrary JavaScript object, adds a pepper and then hashes the data again with a salt.
 * @dataType this is used to provide variability when hashing data
*/
export async function hashData(inputData: any, config: HashDataConfig): Promise<string> {
    const tempData = insertHashPepper(hash(inputData), config.dataType, config.pepperString)
    const hash1 = hash({ data: tempData + getSaltRounds() })
    const temp2 = insertHashPepper(hash1, config.dataType + 2, config.pepperString)
    return await bcrypt.hash(temp2, getSaltRounds());
}

/** used to verify if the hash string is derived from the input data */
export async function compareHash(inputData: any, hashString: string, config: HashDataConfig): Promise<boolean> {
    const tempData = insertHashPepper(hash(inputData), config.dataType, config.pepperString)
    const hash1 = hash({ data: tempData + getSaltRounds() })
    const temp2 = insertHashPepper(hash1, config.dataType + 2, config.pepperString)
    return await bcrypt.compare(temp2, hashString);
}




