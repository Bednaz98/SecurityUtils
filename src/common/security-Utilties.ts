import hash from 'object-hash'
import { convertStringToNumber } from './utilities';



/** gets a pepper string from the systems environment variables*/
export function getPepperString(): string { return hash(process.env.SERVER_HASH_PEPPER_STRING ?? "default") }

/** gets a pepper character from the system pepper string*/
export function getPepper(value: number): string {
    const pepperString = getPepperString();
    return pepperString[value % pepperString.length];
}


export function getInsertIndex(insertString: string, pepper: string, offset: number, insertOpt?: string) {
    const insertVar1 = convertStringToNumber(hash(pepper + insertOpt));
    const insertVar2 = convertStringToNumber(hash(insertOpt ?? "default") + hash(pepper));
    const tempIndex = (insertVar1 + insertVar2) % (insertString.length + offset)
    return tempIndex === 0 ? (insertString.length + offset) : tempIndex

}

export function insertPepper(insertString: string, pepper: string, insertOpt?: string) {
    const insertNumber = getInsertIndex(insertString, pepper, 0, insertOpt)
    return [...insertString.slice(0, insertNumber), pepper, ...insertString.slice(insertNumber)].join('')
}

export function removePepper(insertString: string, pepper: string, insertOpt?: string) {
    const insertNumber = getInsertIndex(insertString, pepper, -1, insertOpt)
    const tempArray = insertString.split('')
    let newArray: string[] = []
    tempArray.forEach((e, i) => {
        if (i !== insertNumber) newArray.push(e)
    })
    return newArray.join('');
}