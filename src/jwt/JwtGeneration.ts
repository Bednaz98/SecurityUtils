import jwt from 'jsonwebtoken';
import { v4 } from 'uuid';
import hash from 'object-hash'
import { JWTConfig } from './types';
import { convertStringToNumber } from '../common/utilities';


let tokenArray: string[] = [];

/**  INTERNAL FUNCTION DO NOT USE DIRECTLY, gets the jwt string from a list of environment variables*/
export function getJWTKey(index: number): string {
    if (tokenArray.length < +1) {
        for (let i = 0; i < 100; i++) {
            let tempKey = process?.env[`SERVER_JWT_KEY${i}`];
            if (tempKey) {
                tokenArray.push(hash(tempKey));
            }

        }
        if (tokenArray.length < 1) {
            tokenArray.push(hash('default'));
        }
    }
    return tokenArray[index % tokenArray.length];
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
/**  INTERNAL FUNCTION DO NOT USE DIRECTLY, returns the issuer string from the systems environment variables*/
export function getIssuer() {
    try {
        return process.env.SERVER_JWT_ISSUER ?? "default";
    } catch (error) {
        return "default"
    }

}
/** generate JWT with input data and config*/
export function generateJWT(data: any, config?: JWTConfig): string {
    const options: jwt.SignOptions = {
        expiresIn: config?.expireTime ?? "1h",
        issuer: getIssuer(),
        subject: config?.subject ?? 'default',
        audience: config?.audience ?? `${getIssuer()}`,
        jwtid: v4(),
    }
    try {
        const stringData = JSON.stringify(data)
        return jwt.sign(data, getJWTKey(getJWTIndex(stringData)), options);
    } catch (error) {
        return 'null';
    }

}

/** retrieve JWT data/ payload */
export function decodeJWT<T>(jwtString: string): T | string | jwt.JwtPayload | null {
    return jwt.decode(jwtString)
}
/** verify if a JWT is valid without decoding the value */
export function verifyJWT(jwtString: string, audience?: string, subject?: string) {
    try {
        const decode = JSON.stringify(decodeJWT(jwtString));
        return Boolean(jwt.verify(jwtString, getJWTKey(getJWTIndex(decode)), { issuer: getIssuer(), clockTolerance: 5, audience, subject }));
    } catch (error) {
        return false;
    }
}