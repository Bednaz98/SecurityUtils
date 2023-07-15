import { generateJWT } from "./JwtGeneration";


/** INTERNAL FUNCTION DO NOT USE DIRECTLY, returns refresh token valid time*/
export function getRefreshValidTime() {
    return Number(process.env.SERVER_GENERIC_USER_REFRESH_TIME ?? 5);
}

/** INTERNAL FUNCTION DO NOT USE DIRECTLY, returns access token valid time*/
export function getAccessValidTime() {
    return Number(process.env.SERVER_GENERIC_USER_ACCESS_TIME ?? 5);
}

/** generate access token for a given user
 * @options this can be used to provide any extra properties that are not "standard" for jwts for your use case. These values will be in the payload of the jwt
*/
export function generateAccessToken(userID: string, options?: any) {
    const subject = options?.subject
    delete options.subject
    return generateJWT({ userID, ... (options ?? {}) }, { expireTime: getAccessValidTime(), subject: (subject ?? "access") });
}

/** generate refresh token for a given user
 * @options this can be used to provide any extra properties that are not "standard" for jwts for your use case. These values will be in the payload of the jwt
*/
export function generateRefreshToken(userID: string, options?: any) {
    const subject = options.subject
    delete options.subject
    return generateJWT({ userID, ...options }, { expireTime: getRefreshValidTime(), subject: (subject ?? "refresh") });
}