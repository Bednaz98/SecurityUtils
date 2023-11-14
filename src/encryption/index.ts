import CryptoJS from 'crypto-js'
import hash from 'object-hash';
import { getPepper, getPepperString, insertPepper, removePepper } from '../common/security-Utilties';
import { convertStringToNumber } from '../common/utilities';
import { keyGroups } from '../common/types';

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, this functions returns an array of the encryption keys on the server */
export function getEncryptionKeyArray(type: number, keyGroup: keyGroups): string[] {
    return keyGroup?.[type] ?? "default"
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  returns the hash value of the input */
export function getEncryptionKey(keyGroup: keyGroups, number: number, keyType: number, varString: string) {

    const encryptionKeys = getEncryptionKeyArray(keyType, keyGroup)
    const index1 = convertStringToNumber(hash(varString + varString));
    const index2 = convertStringToNumber(hash(varString));
    const stringA = encryptionKeys[(number + index1) % encryptionKeys.length]
    const stringB = encryptionKeys[(number + index2) % encryptionKeys.length]
    const hashA = hash(stringA)
    const hashB = hash(stringB)
    let resultKey = '';
    switch (number % 5) {
        case 0: { resultKey = hash(hashA + hashB) + hash(hashA + hashB + varString) + hash(hash(hashA + hashB) + hash(hashA + hashB + varString)); break }
        case 1: { resultKey = hash(hashB + hashA + varString) + hash(varString + hashA + hashB) + hash(hash(hashB + hashA + varString) + hash(varString + hashA + hashB)); break }
        case 3: { resultKey = hash(hashB + varString) + hash(hashA + varString) + hash(hash(hashB + varString) + hash(hashA + varString)); break }
        case 4: { resultKey = hash(varString + hashA) + hash(varString + hashB) + hash(hash(varString + hashA) + hash(varString + hashB)); break }
        default: { resultKey = hash(hashB + varString + hashA) + hash(hashA + varString + hashB) + hash(hash(hashB + varString + hashA) + hash(hashA + varString + hashB)); break }
    }
    return resultKey;
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  gets a single character string from the pepper array*/
export function getEncryptionPepper(index: number) {
    return getPepper(index + 3)
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  used to help give a default option string if one is not provided*/
export function defaultOptionString() {
    return '$$%>';
}


export function singleEncryption(keyGroup: keyGroups, inputData: string, varNum: number, keyType: number, option?: string) {
    const optionVar = (option ?? defaultOptionString())
    const key = getEncryptionKey(keyGroup, varNum, keyType, optionVar)
    const encrypt = CryptoJS.AES.encrypt(JSON.stringify({ inputData }), key).toString()
    return encrypt
}
export function singleDecrypt(keyGroup: keyGroups, cipherText: string, varNum: number, keyType: number, option?: string) {
    const optionVar = (option ?? defaultOptionString());
    const key = getEncryptionKey(keyGroup, varNum, keyType, optionVar)
    const decryptData = CryptoJS.AES.decrypt(cipherText, key).toString(CryptoJS.enc.Utf8)
    return JSON.parse(decryptData).inputData
}


/** this function encrypts a given string, adds a pepper and then encrypts the string again. This should select a "seeded" random encryption key from the supplied encryption key groups.
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
*/
export function encryptText(keyGroup: keyGroups, inputData: string, keyType: number, option?: string) {
    const encrypt1 = singleEncryption(keyGroup, inputData, 1, keyType, option)
    const inertString = insertPepper(encrypt1, getPepper(convertStringToNumber(hash(getPepperString() + option))), option);
    const encrypt = singleEncryption(keyGroup, inertString, 2, keyType, option)
    return encrypt;
}

/** this function decrypts a string value encrypted by this library. The same options passed should be supplied here as passed when using the encrypted data function.
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
*/
export function decryptData(keyGroup: keyGroups, cipherText: string, keyType: number, option?: string) {
    const bytes1 = singleDecrypt(keyGroup, cipherText, 2, keyType, option)
    const removeString = removePepper(bytes1, getPepper(convertStringToNumber(hash(getPepperString() + option))), option)
    const bytes = singleDecrypt(keyGroup, removeString, 1, keyType, option)
    return bytes
}

type acceptedObjectEncryption = { [key: string | number]: string | number | boolean | null | undefined }

/** this function encrypts any arbitrary JavaScript object. 
 * @Note not all data types will work for object values. Accepted values: string | number | boolean | undefined | null
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
 */
export function encryptObjectData(keyGroup: keyGroups, data: acceptedObjectEncryption, keyType: number, optString?: string): { [key: string]: string } {
    const opt = optString ?? "";
    const keys = Object.keys(data)
    const values = Object.values(data).map((e, i) => encryptText(keyGroup, String(e), keyType, (opt + keys[i])))
    return keys.reduce((o, k, i) => ({ ...o, [k]: values[i] }), {} as { [key: string]: string })
}

/** this function decrypts any arbitrary JavaScript object. 
 * @Note not all data types will work for object values. Accepted values: string | number | boolean | undefined | null
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
 */
export function decryptObject<T = ({ [key: string]: string | number | boolean | undefined | null })>(keyGroup: keyGroups, encryptedData: acceptedObjectEncryption, keyType: number, optString?: string): T {
    const opt = optString ?? "";
    const keys = Object.keys(encryptedData)
    const values: any[] = Object.values(encryptedData);
    const decryptValues = values.map((e, i) => {
        const data = decryptData(keyGroup, e, keyType, (opt + keys[i]))

        if (data === "true" || data === "false") return data === "true"
        else if (Number(data)) return Number(data)
        else if (data === "undefined") return undefined
        else if (data === "null") return null
        else return data
    })
    const reduced: any = keys.reduce((o, k, i) => ({ ...o, [k]: decryptValues[i] }), {} as T)
    return reduced;
}

export function NEncryption(keyGroup: keyGroups, inputData: string, keyType: number, option?: string, round: number = 2) {
    let text = inputData
    for (let i = 0; i < round; i++) {
        text = singleEncryption(keyGroup, text, i, keyType, `${option ?? ""}${i}`);
    }
    return text
}

export function NDecryption(keyGroup: keyGroups, inputData: string, keyType: number, option?: string, round: number = 2) {
    let text = inputData
    for (let i = round - 1; i > -1; i--) {
        text = singleDecrypt(keyGroup, text, i, keyType, `${option ?? ""}${i}`);
    }
    return text
}

export default class EncryptionManager {
    private getKeys: () => keyGroups;
    constructor(getKeys: () => keyGroups) {
        this.getKeys = getKeys
    }
    singleEncryption = (inputData: string, varNum: number, keyType: number, option?: string | undefined) => singleEncryption(this.getKeys(), inputData, varNum, keyType, option);
    singleDecrypt = (cipherText: string, varNum: number, keyType: number, option?: string | undefined) => singleDecrypt(this.getKeys(), cipherText, varNum, keyType, option)
    encryptText = (inputData: string, keyType: number, option?: string | undefined) => encryptText(this.getKeys(), inputData, keyType, option)
    decryptData = (cipherText: string, keyType: number, option?: string | undefined) => decryptData(this.getKeys(), cipherText, keyType, option)
    encryptObjectData = (data: acceptedObjectEncryption, keyType: number, optString?: string | undefined) => encryptObjectData(this.getKeys(), data, keyType, optString)
    decryptObject = (data: acceptedObjectEncryption, keyType: number, optString?: string | undefined) => decryptObject(this.getKeys(), data, keyType, optString)
    NEncryption = (inputData: string, keyType: number, option?: string | undefined, round?: number) => NEncryption(this.getKeys(), inputData, keyType, option, round)
    NDecryption = (inputData: string, keyType: number, option?: string | undefined, round?: number) => NDecryption(this.getKeys(), inputData, keyType, option, round)
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


