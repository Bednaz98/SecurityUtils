import CryptoJS from 'crypto-js'
import hash from 'object-hash';
import { getPepper, getPepperString, insertPepper, removePepper } from '../common/security-Utilties';
import { convertStringToNumber } from '../common/utilities';

let encryptionKeysA: string[] = [];
let encryptionKeysB: string[] = [];

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, this functions returns an array of the encryption keys on the server */
export function getEncryptionKeyArray(type: boolean): string[] {
    return type ? encryptionKeysB : encryptionKeysA;
}
/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  clears the keys at run time*/
export function clearKeys() {
    encryptionKeysA = []
    encryptionKeysB = []
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  this function initializes the getting the encryption key array*/
export function initEncryptionKeys() {
    if (encryptionKeysA.length < 2) {
        for (let i = 0; i < 100; i++) {
            const key = process.env[`SERVER_ENCRYPTION_A${i}`];
            if (key) {
                encryptionKeysA.push(key);
            }
        }
    }
    if (encryptionKeysA.length < 2) {
        encryptionKeysA.push('defaultA1');
        encryptionKeysA.push('default2A');
    }

    if (encryptionKeysB.length < 2) {
        for (let i = 0; i < 100; i++) {
            const key = process.env[`SERVER_ENCRYPTION_B${i}`];
            if (key) {
                encryptionKeysB.push(key);
            }
        }
    }
    if (encryptionKeysB.length < 2) {
        encryptionKeysB.push('defaultB1');
        encryptionKeysB.push('defaultB2');
    }

}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  returns the hash value of the input */
export function getEncryptionKey(number: number, keyType: boolean, varString: string) {
    initEncryptionKeys();
    const encryptionKeys = getEncryptionKeyArray(keyType)
    const index1 = convertStringToNumber(hash(varString + varString));
    const index2 = convertStringToNumber(hash(varString));
    const stringA = encryptionKeys[(number + index1) % encryptionKeys.length]
    const stringB = encryptionKeys[(number + index2) % encryptionKeys.length]
    const hashA = hash(stringA)
    const hashB = hash(stringB)
    switch (number % 5) {
        case 0: return hash(hashA + hashB) + hash(hashA + hashB + varString) + hash(hash(hashA + hashB) + hash(hashA + hashB + varString));
        case 1: return hash(hashB + hashA + varString) + hash(varString + hashA + hashB) + hash(hash(hashB + hashA + varString) + hash(varString + hashA + hashB));
        case 3: return hash(hashB + varString) + hash(hashA + varString) + hash(hash(hashB + varString) + hash(hashA + varString));
        case 4: return hash(varString + hashA) + hash(varString + hashB) + hash(hash(varString + hashA) + hash(varString + hashB));
        default: return hash(hashB + varString + hashA) + hash(hashA + varString + hashB) + hash(hash(hashB + varString + hashA) + hash(hashA + varString + hashB));
    }
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  gets a single character string from the pepper array*/
export function getEncryptionPepper(index: number) {
    return getPepper(index + 3)
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY,  used to help give a default option string if one is not provided*/
export function defaultOptionString() {
    return '$$%>';
}


/** this function encrypts a given string, adds a pepper and then encrypts the string again. This should select a "seeded" random encryption key from the supplied encryption key groups.
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
*/
export function encryptText(inputData: string, keyType: boolean, option?: string) {
    const optionVar = (option ?? defaultOptionString())
    const encrypt1 = CryptoJS.AES.encrypt(inputData, getEncryptionKey(1, keyType, optionVar)).toString();
    const inertString = insertPepper(encrypt1, getPepper(convertStringToNumber(hash(getPepperString() + option))), option);
    const encrypt = CryptoJS.AES.encrypt(inertString, getEncryptionKey(2, keyType, optionVar)).toString();
    return encrypt;
}

/** this function decrypts a string value encrypted by this library. The same options passed should be supplied here as passed when using the encrypted data function.
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
*/
export function decryptData(cipherText: string, keyType: boolean, option?: string) {
    const optionVar = (option ?? defaultOptionString());
    const bytes1 = CryptoJS.AES.decrypt(cipherText, getEncryptionKey(2, keyType, optionVar)).toString(CryptoJS.enc.Utf8);
    const removeString = removePepper(bytes1, getPepper(convertStringToNumber(hash(getPepperString() + option))), option)
    const bytes = CryptoJS.AES.decrypt(removeString, getEncryptionKey(1, keyType, optionVar)).toString(CryptoJS.enc.Utf8)
    return bytes.replace(optionVar, "");
}

/** this function encrypts any arbitrary JavaScript object. 
 * @Note not all data types will work for object values. Accepted values: string | number | boolean | undefined | null
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
 */
export function encryptObjectData(data: { [key: string | number]: string | number | boolean | undefined | null }, keyType: boolean, optString?: string): { [key: string]: string } {
    const opt = optString ?? "";
    const keys = Object.keys(data)
    const values = Object.values(data).map((e, i) => encryptText(String(e), keyType, (opt + keys[i])))
    return keys.reduce((o, k, i) => ({ ...o, [k]: values[i] }), {} as { [key: string]: string })
}

/** this function decrypts any arbitrary JavaScript object. 
 * @Note not all data types will work for object values. Accepted values: string | number | boolean | undefined | null
 * @keyType denotes whether or not key group A or B should be utilized
 * @Options is used to help give variation when encrypting data. This helps choosing different encryption keys when encrypting multiple data entries
 */
export function decryptObject<T = ({ [key: string]: string | number | boolean | undefined | null })>(encryptedData: { [key: string | number]: string | number | boolean | undefined | null }, keyType: boolean, optString?: string): T {
    const opt = optString ?? "";
    const keys = Object.keys(encryptedData)
    const values: any[] = Object.values(encryptedData);
    const decryptValues = values.map((e, i) => {
        const data = decryptData(e, keyType, (opt + keys[i]))

        if (data === "true" || data === "false") return data === "true"
        else if (Number(data)) return Number(data)
        else if (data === "undefined") return undefined
        else if (data === "null") return null
        else return data
    })
    const reduced: any = keys.reduce((o, k, i) => ({ ...o, [k]: decryptValues[i] }), {} as T)
    return reduced;
}


