# SecurityUtils
This is a utility package that combines using 'bcrypt' 'crypto-js', 'jsonwebtoken' and 'object-hash' for storing information in a database either by hash or encryption. It also supports the rotation of encryption to maintain compatibility when performing security key rotation.

4.0 >= hash had a major redesign. For the previous version, check npm version and refer to the readme for each version.



# Hash functions

There are hash and compareHash functions that can be used for hash and salting passwords. This is done using bcrypt and object-has.

The expectation is to include a "pepperArray" which is an array of strings. The dataTypes is then used to help select 3 unique strings from the array. Then those strings are hashed together. A single character is then inserted into the hash string. The result is then hashed and pepper again (with different strings generated from the pepper array) before finally salting the final value.

``` typescript
import {hashData, compareHash} from "@jabz/security-utils";

const inputData: any = {/*  any data you want  */}
const  dataType: number = 0 // used to provide variation
const  pepperString: string[] = [/* treat as api keys*/] // used for generating pepper
const hashData:string = hashData(inputData,  dataType: number, pepperString: string[]) // returns a hash string 
const compareHash = compareHash(hashData, dataType: number, hashString: string, pepperString: string[]) //returns boolean if match

```

# JWT Manager

This is a class to help manage the generation and validation of JWTs. Instead of using jwtAPI keys for signing the token, this class will take up to 3 strings from the kwt keys provided and hash a new one at run time.

```typescript 
import {JWTManager, JWTManagerConfig} from "@jabz/security-utils";
const keys = ()=>{/* some implementation to get the API keys*/};
const config: JWTManagerConfig  = {
    getJWTKey: () => string[];
    issuer: string;
    JWTConfig?: JWTConfig | undefined;
    accessTokenValidTime?: number
    refreshTokenValidTime?: number
};

const jwtManager = new JWTManager(config);

//The following are provided
    jwtManager.generateJWT(data: any) // values in the config are automatically injected. the data parameter can be used to override and inject any data field needed
    jwtManager.generateAccessToken(userID: string, options?: any, audience?: string) // used for making access token, options is used for injecting properties and overriding
    jwtManager.generateRefreshToken(userID: string, options?: any, audience?: string) // used for making refresh token, options is used for injecting properties and overriding
    jwtManager.verifyJWT (jwtString: string, audience?: string, subject?: string) // validates whether or not the jwt is authentic. Audience and Subject are optional
    jwtManager.decodeJWT(jwtString: string) // returns the data within a jwt
    jwtManager.deleteNoneUniqueJWTProperties({/*contents of a jwt*/} :any) //This is a utility function used to remove ALL "STANDARD" properties within a JWT leaving only custom properties.
```


# Encryption Manager

With this class, a "single encryption step" goes as follows:
- pull 3 
- encrypt the data once
- add a pepper
- encrypt the data again

This library supports "single" encryption, N encryption and encryption fill objects.

```typescript 
import {EncryptionManager} from "@jabz/security-utils";
const getKeys: ()string[] => [/*your API keys*/] // used to get encryption keys
const encryptManager = new EncryptionManager(getKeys)

//The following are provided
    // used as a base wrapper around crypto-js for handling encryption. This is not intended to be used directly
    // encryptVar - used for variation when encryption, eg userID, specific field ...., this helps make two closely related data have completely different encryption keys
    encryptManager.singleEncryption(inputData: string, keyType: string | number, option?: string | number | undefined) 
    encryptManager.singleDecrypt(cipherText: string, keyType: string | number, option?: string | number | undefined)

    //This is the primary function intended to be used for encryption. This implements the described process above
    encryptManager.encryptText(inputData: string, keyType: string | number, pepperString: string[], option?: string | undefined)
    encryptManager.decryptData(cipherText: string, keyType: string | number, pepperString: string[], option?: string | undefined)

    //This applies the same encryption as above but does it so "N" times, the round number is the amount of times it will encrypt the data. The default is 2.
    encryptManager.NEncryption(inputData: string, keyType: string | number, option?: string | number | undefined, round?: number)
    encryptManager.NDecryption(cipherText: string, keyType: string | number, option?: string | number | undefined, round?: number)

    //This can be used to encrypt entire objects. This can only take objects that are a single layer of just primitives (booleans, numbers, strings). NaN is converted to null.
    encryptManager.encryptObjectData(data: acceptedObjectEncryption, keyType: string | number, pepperString: string[], optString?: string | number | undefined)
    encryptManager.decryptObject(encryptedObject: acceptedObjectEncryption, keyType: string | number, pepperString: string[], optString?: string | number | undefined)
```
