import { convertStringToNumber } from '@jabz/math-js';
import hash from 'object-hash'
import CryptoJS from 'crypto-js'


/** INTERNAL FUNCTION DO NOT USE DIRECTLY, gets a pepper character from the system pepper string*/
export function getPepper(value: number, pepperString: string[]): string {
    const value1 = pepperString[value % pepperString.length];
    const value2 = pepperString[((value + 1) * 2) % pepperString.length];
    const value3 = pepperString[((value + 2) * 3) % pepperString.length];
    return hash({ value1, value2, value3 })[value % pepperString.length];
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

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  this is used to hash multiple keys into a unique runtime key */
export function hashAPIKey(inputKeys: string[], option?: any) {
    const key1 = hash({ val: inputKeys[0] })
    const key2 = hash({ val: inputKeys[1] })
    const key3 = hash({ val: inputKeys[2] })
    return hash({ key1, key2, key3, option });
}