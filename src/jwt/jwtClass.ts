import { generateAccessToken, generateRefreshToken } from './GenerateUserTokens'
import { decodeJWT, generateJWT, verifyJWT } from './JwtGeneration'
import { JWTConfig } from './types'



export interface JWTManagerConfig {
    getJWTKey: () => string[];
    issuer: string;
    JWTConfig?: JWTConfig | undefined;
    accessTokenValidTime?: number
    refreshTokenValidTime?: number
}

export default class JWTManager {
    private getJWTKey: () => string[]
    private issuer: string
    private JWTConfig?: JWTConfig | undefined
    private accessTokenValidTime: number
    private refreshTokenValidTime: number
    constructor(config: JWTManagerConfig) {
        this.getJWTKey = config.getJWTKey;
        this.issuer = config.issuer;
        this.JWTConfig = config.JWTConfig;
        this.accessTokenValidTime = config.accessTokenValidTime ?? 0;
        this.refreshTokenValidTime = config.refreshTokenValidTime ?? 0;
    }
    generateJWT = (data: any) => generateJWT(data, this.issuer, this.getJWTKey(), this.JWTConfig)
    decodeJWT = decodeJWT
    verifyJWT = (jwtString: string, audience?: string, subject?: string) => verifyJWT(jwtString, this.getJWTKey(), this.issuer, audience, subject)
    generateAccessToken = (userID: string, options?: any, audience?: string) => generateAccessToken(userID, this.issuer, this.getJWTKey(), this.accessTokenValidTime, options, audience)
    generateRefreshToken = (userID: string, options?: any, audience?: string) => generateRefreshToken(userID, this.issuer, this.getJWTKey(), this.refreshTokenValidTime, options, audience)
}