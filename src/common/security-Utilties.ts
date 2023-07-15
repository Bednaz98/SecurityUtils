import hash from 'object-hash'
import { convertStringToNumber } from './utilities';



/** INTERNAL FUNCTION DO NOT USE DIRECTLY, gets a pepper string from the systems environment variables*/
export function getPepperString(): string { return hash(process.env.SERVER_HASH_PEPPER_STRING ?? "default") }

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, gets a pepper character from the system pepper string*/
export function getPepper(value: number): string {
    const pepperString = getPepperString();
    return pepperString[value % pepperString.length];
}


/** INTERNAL FUNCTION DO NOT USE DIRECTLY, this functions uses the input parameters to get an index where a pepper character will be inserted into a string */
export function getInsertIndex(insertString: string, pepper: string, offset: number, insertOpt?: string): number {
    const insertVar1 = convertStringToNumber(hash(pepper + insertOpt));
    const insertVar2 = convertStringToNumber(hash(insertOpt ?? "default") + hash(pepper));
    const tempIndex = (insertVar1 + insertVar2) % (insertString.length + offset)
    return tempIndex === 0 ? (insertString.length + offset) : tempIndex

}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, this function inserts a pepper character into a string*/
export function insertPepper(insertString: string, pepper: string, insertOpt?: string) {
    const insertNumber = getInsertIndex(insertString, pepper, 0, insertOpt)
    return [...insertString.slice(0, insertNumber), pepper, ...insertString.slice(insertNumber)].join('')
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  this function removes a pepper from a string */
export function removePepper(insertString: string, pepper: string, insertOpt?: string) {
    const insertNumber = getInsertIndex(insertString, pepper, -1, insertOpt)
    const tempArray = insertString.split('')
    const newArray: string[] = []
    tempArray.forEach((e, i) => {
        if (i !== insertNumber) newArray.push(e)
    })
    return newArray.join('');
}