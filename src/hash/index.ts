import bcrypt from 'bcrypt';
import hash from 'object-hash'
import { getPepper, getPepperString } from '../common/security-Utilties';
import { convertStringToNumber } from '../common/utilities';
/**gets the number of routes to salt a value*/
export function getSaltRounds(): number {
    return Number(process.env.SERVER_HASH_SALT_ROUNDS ?? 0);
};


/** inserts pepper into a given string*/
export function insertPepper(insertString: string, dataType: number): string {
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

/** double hashes and peppers any input data and returns a salted string */
export async function hashData(inputData: any, dataType: number): Promise<string> {
    const tempData = insertPepper(hash(inputData), dataType)
    return await bcrypt.hash(tempData, getSaltRounds());
}

/** used to verify if the hash string is derived from the input data*/
export async function compareHash(inputData: any, dataType: number, hashString: string): Promise<boolean> {
    const tempData = insertPepper(hash(inputData), dataType)
    return await bcrypt.compare(tempData, hashString);
}




