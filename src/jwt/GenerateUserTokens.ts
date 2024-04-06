import { generateJWT } from "./JwtGeneration";

/** generate access token for a given user
 * @options this can be used to provide any extra properties that are not "standard" for jwts for your use case. These values will be in the payload of the jwt
*/
export function generateAccessToken(userID: string, issuer: string, keyArray: string[], validTime: number | string, options?: any, audience?: string) {
    return generateJWT({ userID, ... (options ?? {}) }, issuer, keyArray, { audience, expireTime: validTime, subject: (options?.subject ?? "access") });
}

/** generate refresh token for a given user
 * @options this can be used to provide any extra properties that are not "standard" for jwts for your use case. These values will be in the payload of the jwt
*/
export function generateRefreshToken(userID: string, issuer: string, keyArray: string[], validTime: number | string, options?: any, audience?: string) {
    return generateJWT({ userID, ...options }, issuer, keyArray, { audience, expireTime: validTime, subject: (options?.subject ?? "refresh") });
}