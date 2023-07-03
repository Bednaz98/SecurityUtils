import { JwtPayload } from "jsonwebtoken";

/** configuration for how JWT should be created by default*/
export interface JWTConfig {
    expireTime: string | number | undefined,
    subject?: string,
    audience?: string
}

/** refresh token payload*/
export interface RefreshToken extends JwtPayload {
    userID: string,
    userName: string,
    //@ts-ignore
    [key: string]: string
}
