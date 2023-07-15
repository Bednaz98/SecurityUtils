# SecurityUtils
This is a utility package that combines using 'bcrypt' 'crypto-js', 'jsonwebtoken' and 'object-hash' for storing information in a data base either by hash or encryption.


# Overview

## Setup
This library is meant to be a "plug and play" solution for handing data encryption and password hashing within a database. In your environment setting the following should be setup (see example .env file for specific notes):
 - SERVER_HASH_PEPPER_STRING            (string)
 - SERVER_HASH_SALT_ROUNDS              (integer)
 - SERVER_GENERIC_USER_REFRESH_TIME     (integer)
 - SERVER_GENERIC_USER_ACCESS_TIME      (integer)
 - SERVER_JWT_ISSUER                    (optional string, default value: 'default')
 - SERVER_JWT_KEY#                      (See notes below) (group A/B implementation is pending in 2.x)
 - SERVER_ENCRYPTION_A#                 (See notes below)
 - SERVER_ENCRYPTION_B#                 (See notes below)

 All functions in this library are exported for use but some are marked as "INTERNAL FUNCTION DO NOT USE DIRECTLY" in the intellisense. It is not recommended to use these functions unless there is a specific use case or a customized function is needed that follow simple design patterns. These function have comments in the source but no further documentation will be provided.

## key usage
For both JWT and encryption, up to 100 different keys can be used. These keys are not used directly. Instead, each key used is hashed before it is utilized by this library. For JWT only a single hash is done. For encryption keys, two different keys are selected and hash together, appended and used in different arrangements.

The goal is to have group A and B keys for routine maintenance. When implementations this functions, there are parameters for key groups. First try group A and see if you get a sensible result, then try group B. Example: switching jwt keys monthly, first start with group A, then migrate them to group B and then replace group A. After another month the repeat the process with new keys.

## Pepper string
The pepper string provide a different pepper each time one is needed instead of hard coding a single value to use. The string provided sound be randomized.

## Encrypted values
When passing a string to the encryption function, the first it will be encrypted as expected, then a pepper will be added, then the string will be encrypted again.

## Hash values
When passing data to the hash function, it will first hash the data, then add a pepper, then  it will be hashed again using a salt value.

## JWT
Any generic JWT can be generated. This library has default functions for generically making refresh and access tokens.


# Example use cases

## Encryption
``` TypeScript
// Encryption

import  {encryptText, decryptData, encryptObjectData, decryptObject} from '@jabz/security-utils'

// main example
const stringToEncrypt1 = "testing string";
const option1 = "used to help get different encryption for each value used"
const encryptedString1 = encryptText(stringToEncrypt, true,option1)
console.log(encryptedString1)
const decrypt = decryptData(encryptedString1, true,option1 )
console.log(decrypt) // should be the same as above

// variation example
const stringToEncrypt2 = "testing string";
const option2 = "used to help get different encryption for each value used"
const encryptedString2 = encryptText(stringToEncrypt, true,option2)
console.log(encryptedString2) // this should look different from the other encryption string
const decrypt = decryptData(encryptedString2, true,option2 )
console.log(decrypt) // should be the same as above


// object encryption

const testObject = {
    string:"test String 123 $$$"
    number:4
    boolean: true
    nullValue:null
    undefinedValue:undefined
}
const option = "used to help get different encryption for each value used"
const encryptedObject = encryptObjectData(testObject,true, option)
console.log(encryptedObject)
const decryptedObject = decryptObject(encryptedObject,true, option)
console.log(decryptedObject) // should be the same as above

```

## Hash (for passwords)
 
``` TypeScript
import  {hashData, compareHash} from '@jabz/security-utils'

const inputData = {test:"value", value:5} // this can be any data value, more commonly this would be a string e.g. a password from a user

const dataType1 = 5 // used for variation
const hashedValue1 = hashData(inputData, dataType1)
console.log(hashedValue1)
const result1 = compareHash(hashedValue1, dataType1)
console.log(result1) // should be true

const hashedValue2 = hashData(inputData, 2)
console.log(hashedValue2) // should look different from the one above
const result2 = compareHash(hashedValue2, dataType)
console.log(result2) // should be false

```

## JWT

``` TypeScript
import { deleteNoneUniqueJWTProperties, generateJWT, decodeJWT, generateAccessToken, generateRefreshToken} from  '@jabz/security-utils'




const data = {example:3} // anything to inject into the payload
const JWTConfig  = { // optional parameters
    expireTime: "1d",
    subject: "example",
    audience: "your intended backend service"
}

// Generic JWT
const genericJWT = generateJWT(data,JWTConfig )

// retrieve jwt payload
const decodedValues = decodeJWT(genericJWT)
console.log(decodedValues) // should be the same as above plus additional standard jwt properties

// utility function
const payload =  deleteNoneUniqueJWTProperties(genericJWT)
console.log(payload) // this should return everything that is not expected within a standard JWT


const result1 = verifyJWT(genericJWT)
console.log(result1) // should return true

// parameters here are optional
const result2 = verifyJWT(genericJWT, "audience", "subject")
console.log(result2) // should return false 



const userID "exampleUserID"
const options {} // optional data to inject

// this will automatically assign for issuer and exp time based on environment config
const accessToken = generateAccessToken(userID, options)
const refreshToken = generateRefreshToken(userID, options)

```

