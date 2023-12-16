import jwt from 'jsonwebtoken';
import { v4 } from 'uuid';
import { JWTConfig } from './types';
import { convertStringToNumber } from '@jabz/math-js';
import { hashAPIKey } from '../common';



/**  INTERNAL FUNCTION DO NOT USE DIRECTLY, gets the jwt string from a list of environment variables*/
export function getJWTKey(index: number, keyArray: string[]): string {
    const key1 = keyArray[index + 1 % keyArray.length]
    const key2 = keyArray[(index * 3 + 2) % keyArray.length]
    const key3 = keyArray[(index * 2 + 3) % keyArray.length]
    return hashAPIKey([key1, key2, key3,], index);
}

/** remove all standard JWT properties to get back injected data*/
export function deleteNoneUniqueJWTProperties(JWTObject: any) {
    let newObject = { ...JWTObject };
    delete newObject.aud;
    delete newObject.exp;
    delete newObject.iat;
    delete newObject.iss;
    delete newObject.jti;
    delete newObject.nbf;
    delete newObject.sub;
    return { ...newObject };
}
/** INTERNAL FUNCTION DO NOT USE DIRECTLY, converts a JWT into a number*/
export function getJWTIndex(jwtString: string | null) {
    const decode = decodeJWT<string | jwt.JwtPayload | null>(jwtString ?? "");
    if (typeof decode === 'string') return convertStringToNumber(decode);
    else if (decode === null) return 0;
    else {
        const jsonString = JSON.stringify(deleteNoneUniqueJWTProperties(decode))
        return convertStringToNumber(JSON.stringify(jsonString));
    }
}

/** generate JWT with input data and config*/
export function generateJWT(data: any, issuer: string, keyArray: string[], config?: JWTConfig): string {
    const options: jwt.SignOptions = {
        expiresIn: config?.expireTime ?? "1h",
        issuer,
        subject: config?.subject ?? 'default',
        audience: config?.audience ?? issuer,
        jwtid: v4(),
    }
    try {
        const stringData = JSON.stringify(data)
        return jwt.sign(data, getJWTKey(getJWTIndex(stringData), keyArray), options);
    } catch (error) {
        return 'null';
    }

}

/** retrieve JWT data/ payload */
export function decodeJWT<T>(jwtString: string): T | string | jwt.JwtPayload | null {
    return jwt.decode(jwtString)
}
/** verify if a JWT is valid without decoding the value */
export function verifyJWT(jwtString: string, keyArray: string[], issuer: string, audience?: string, subject?: string) {
    try {
        const decode = JSON.stringify(decodeJWT(jwtString));
        return Boolean(jwt.verify(jwtString, getJWTKey(getJWTIndex(decode), keyArray), { issuer, clockTolerance: 5, audience, subject }));
    } catch (error) {
        return false;
    }
}