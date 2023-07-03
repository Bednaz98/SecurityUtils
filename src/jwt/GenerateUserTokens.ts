import { generateJWT } from "./JwtGeneration";


/** returns refresh token valid time*/
export function getRefreshValidTime() {
    return Number(process.env.SERVER_GENERIC_USER_REFRESH_TIME ?? 5);
}

/** returns access token valid time*/
export function getAccessValidTime() {
    return Number(process.env.SERVER_GENERIC_USER_ACCESS_TIME ?? 5);
}

/** generate access token for a given user*/
export function generateAccessToken(userID: string, options?: any) {
    const subject = options?.subject
    delete options.subject
    return generateJWT({ userID, ... (options ?? {}) }, { expireTime: getAccessValidTime(), subject: (subject ?? "access") });
}

/** generate refresh token for a given user*/
export function generateRefreshToken(userID: string, options?: any) {
    const subject = options.subject
    delete options.subject
    return generateJWT({ userID, ...options }, { expireTime: getRefreshValidTime(), subject: (subject ?? "refresh") });
}