import CryptoJS from 'crypto-js'
import hash from 'object-hash';
import { getPepper, hashAPIKey, insertPepper, removePepper } from '../common/security-Utilties';

import { convertStringToNumber } from '@jabz/math-js';

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, this functions returns an array of the encryption keys on the server */
export function getEncryptionKeyArray(type: string | number, encryptionStrings: string[]): string {
    const index = convertStringToNumber(hash({ type }))
    return encryptionStrings[index % encryptionStrings.length]
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  returns the hash value of the input */
export function getEncryptionKey(encryptionStrings: string[], keyType: string | number, varString?: string | number) {
    const hashA = getEncryptionKeyArray(keyType, encryptionStrings)
    const hashB = getEncryptionKeyArray(keyType, encryptionStrings)
    const hashC = getEncryptionKeyArray(keyType, encryptionStrings)
    return JSON.stringify(hashAPIKey([hashA, hashB, hashC], `${keyType}${varString}`))
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  gets a single character string from the pepper array*/
export function getEncryptionPepper(index: number, pepperArray: string[]) {
    return getPepper(index + 3, pepperArray)
}



export function singleEncryption(encryptionStrings: string[], inputData: string, encryptVar: string | number, keyType?: string | number) {
    const key = getEncryptionKey(encryptionStrings, encryptVar, keyType)
    const encrypt = CryptoJS.AES.encrypt(JSON.stringify({ inputData }), key).toString()
    return encrypt
}
export function singleDecrypt(encryptionStrings: string[], cipherText: string, encryptVar: string | number, keyType?: string | number) {
    const key = getEncryptionKey(encryptionStrings, encryptVar, keyType)
    const decryptData = CryptoJS.AES.decrypt(cipherText, key).toString(CryptoJS.enc.Utf8)
    return JSON.parse(decryptData).inputData
}


/** this function encrypts a given string, adds a pepper and then encrypts the string again. This should select a "seeded" random encryption key from the supplied encryption key groups.
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
*/
export function encryptText(encryptionStrings: string[], inputData: string, keyType: string | number, pepperStringArray: string[], option?: string) {
    const encrypt1 = singleEncryption(encryptionStrings, inputData, `${keyType}1`, option)
    const pepper = getPepper(convertStringToNumber(hash({ pepperLength: pepperStringArray.length, option })), pepperStringArray)
    const inertString = insertPepper(encrypt1, pepper, option);
    const encrypt = singleEncryption(encryptionStrings, inertString, `${keyType}2`, option)
    return encrypt;
}

/** this function decrypts a string value encrypted by this library. The same options passed should be supplied here as passed when using the encrypted data function.
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
*/
export function decryptData(encryptionStrings: string[], cipherText: string, keyType: string | number, pepperStringArray: string[], option?: string) {
    const bytes1 = singleDecrypt(encryptionStrings, cipherText, `${keyType}2`, option)
    const pepper = getPepper(convertStringToNumber(hash({ pepperLength: pepperStringArray.length, option })), pepperStringArray)
    const removeString = removePepper(bytes1, pepper, option)
    const bytes = singleDecrypt(encryptionStrings, removeString, `${keyType}1`, option)
    return bytes
}

type acceptedObjectEncryption = { [key: string | number]: string | number | boolean | null | undefined }

/** this function encrypts any arbitrary JavaScript object. 
 * @Note not all data types will work for object values. Accepted values: string | number | boolean | undefined | null
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
 */
export function encryptObjectData(encryptionStrings: string[], data: acceptedObjectEncryption, keyType: string | number, pepperString: string[], optString?: string | number): { [key: string]: string } {
    const opt = optString ?? "";
    const keys = Object.keys(data)
    const values = Object.values(data).map((e, i) => encryptText(encryptionStrings, String(e), keyType, pepperString, (opt + keys[i])))
    return keys.reduce((o, k, i) => ({ ...o, [k]: values[i] }), {} as { [key: string]: string })
}

/** this function decrypts any arbitrary JavaScript object. 
 * @Note not all data types will work for object values. Accepted values: string | number | boolean | undefined | null
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
 */
export function decryptObject<T = ({ [key: string]: string | number | boolean | undefined | null })>(encryptionStrings: string[], encryptedData: acceptedObjectEncryption, keyType: string | number, pepperString: string[], optString?: string | number): T {
    const opt = optString ?? "";
    const keys = Object.keys(encryptedData)
    const values: any[] = Object.values(encryptedData);
    const decryptValues = values.map((e, i) => {
        const data = decryptData(encryptionStrings, e, keyType, pepperString, (opt + keys[i]))

        if (data === "true" || data === "false") return data === "true"
        else if (Number(data)) return Number(data)
        else if (data === "undefined") return undefined
        else if (data === "null") return null
        else return data
    })
    const reduced: any = keys.reduce((o, k, i) => ({ ...o, [k]: decryptValues[i] }), {} as T)
    return reduced;
}

export function NEncryption(encryptionStrings: string[], inputData: string, keyType: string | number, option?: string | number, round: number = 2) {
    let text = inputData
    for (let i = 0; i < round; i++) {
        text = singleEncryption(encryptionStrings, text, keyType, `${option ?? ""}${i}`);
    }
    return text
}

export function NDecryption(encryptionStrings: string[], inputData: string, keyType: string | number, option?: string | number, round: number = 2) {
    let text = inputData
    for (let i = round - 1; i > -1; i--) {
        text = singleDecrypt(encryptionStrings, text, keyType, `${option ?? ""}${i}`);
    }
    return text
}

export default class EncryptionManager {
    private getKeys: () => string[];
    constructor(getKeys: () => string[]) {
        this.getKeys = getKeys
    }
    singleEncryption = (inputData: string, keyType: string | number, option?: string | number | undefined) => singleEncryption(this.getKeys(), inputData, keyType, option);
    singleDecrypt = (cipherText: string, keyType: string | number, option?: string | number | undefined) => singleDecrypt(this.getKeys(), cipherText, keyType, option)
    encryptText = (inputData: string, keyType: string | number, pepperString: string[], option?: string | undefined) => encryptText(this.getKeys(), inputData, keyType, pepperString, option)
    decryptData = (cipherText: string, keyType: string | number, pepperString: string[], option?: string | undefined) => decryptData(this.getKeys(), cipherText, keyType, pepperString, option)
    encryptObjectData = (data: acceptedObjectEncryption, keyType: string | number, pepperString: string[], optString?: string | number | undefined) => encryptObjectData(this.getKeys(), data, keyType, pepperString, optString)
    decryptObject = (encryptedObject: acceptedObjectEncryption, keyType: string | number, pepperString: string[], optString?: string | number | undefined) => decryptObject(this.getKeys(), encryptedObject, keyType, pepperString, optString)
    NEncryption = (inputData: string, keyType: string | number, option?: string | number | undefined, round?: number) => NEncryption(this.getKeys(), inputData, keyType, option, round)
    NDecryption = (cipherText: string, keyType: string | number, option?: string | number | undefined, round?: number) => NDecryption(this.getKeys(), cipherText, keyType, option, round)
}

// /** experiment*/
// export function rotateEncryptionDataAB(keyGroup: keyGroups, encryptedData: string, transitionType: boolean, option?: string) {
//     const fetchIndex = !transitionType ? 0 : 1
//     const switchIndex = !transitionType ? 1 : 2
//     try {
//         const temp = decryptData(keyGroup, encryptedData, fetchIndex, option);
//         if (temp.includes(getEncryptionCheckString())) return encryptText(keyGroup, temp, switchIndex, option).replace(getEncryptionCheckString(), "");
//         return null
//     } catch (error) {
//         expectedWarning()
//         console.warn(JSON.stringify(error))
//         return null
//     }

// }

// /** experiment*/
// export function encryptRotationText(inputData: string, keyType: boolean, option?: string) {
//     return encryptText(`${inputData}${getEncryptionCheckString()}`, keyType, option)

// }

// /** experiment*/
// export function decryptRotationText(cipherText: string, option?: string): string | undefined {
//     let check1: string = '';
//     try { check1 = decryptData(cipherText, true, option) } catch (error) { expectedWarning(); console.info(JSON.stringify(error)) }
//     if (check1.includes(getEncryptionCheckString())) return check1.replace(getEncryptionCheckString(), '');
//     let check2: string = '';
//     try { check2 = decryptData(cipherText, false, option) } catch (error) { expectedWarning(); console.info(JSON.stringify(error)) }
//     if (check2.includes(getEncryptionCheckString())) return check2.replace(getEncryptionCheckString(), '');
// }


