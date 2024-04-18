"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const crypto = require('crypto');

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = { 
      kvs: Date.now(),
      iv: getRandomBytes(16),
      salt: getRandomBytes(16)
    };
    this.secrets = {
    };

    
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const master_key = await subtle.importKey("raw", stringToBuffer(password),"PBKDF2", false, ["deriveKey"]);
    const hmac1 = crypto.createHmac('sha256', master_key);
    const data_domain = hmac1.update('MAC Domain Name');
    const domain_hmac = data_domain.digest('hex').substring(0, 32);

    const hmac2 = crypto.createHmac('sha256', master_key);
    const data_pw = hmac2.update('Encrypt Password');
    const pw_hmac = data_pw.digest('hex').substring(0, 32);

    const aesKey = await subtle.importKey(
      "raw", stringToBuffer(pw_hmac), "AES-GCM", true, ["encrypt", "decrypt"]);

    const keychain = new Keychain()
    keychain.data = {}
    keychain.secrets = {
      master_password : password,
      hmac_for_domain_name: domain_hmac,
      hmac_for_password: pw_hmac,
      aesKey: aesKey
    }
    return keychain
}


  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {

    // const decodeKeysAndValues = (obj) => {
    //   if (typeof obj !== 'object' || obj === null) {
    //     return obj; // If it's not an object, return as is
    //   }
    
    //   const decodedObj = {};
    //   for (const key in obj) {
    //     if (Object.prototype.hasOwnProperty.call(obj, key)) {
    //       const decodedKey = Buffer.from(key, 'base64').toString('utf-8');
    //       const value = obj[key];
    //       decodedObj[decodedKey] = typeof value === 'object' ? decodeKeysAndValues(value) : Buffer.from(value, 'base64').toString('utf-8'); // Recursively decode nested objects or decode values
    //     }
    //   }
    //   return decodedObj;
    // };

    const jsonData = JSON.parse(repr);
    let actual_data = jsonData["data"]
    let decoded_data = Buffer.from(actual_data,"base64").toString("utf-8")

    let actual_parse = JSON.parse(decoded_data)


    const buffer_data = stringToBuffer(decoded_data);
    const buffer_checksum = await subtle.digest("SHA-256", buffer_data);
    const string_checksum = bufferToString(buffer_checksum)


    if (trustedDataCheck && string_checksum !== trustedDataCheck) {
        throw new Error("Integrity check failed. Provided trustedDataCheck does not match the checksum.");
    }

    const recover_kvs = new Keychain();
    recover_kvs.data = actual_parse.data;
    recover_kvs.secrets = actual_parse.secrets;

    if (password == recover_kvs.secrets.master_password) {
      return recover_kvs;
    } else {
      throw "Wrong password"
    }

    
}



  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // Encode the data as base64
    const encodeKeysAndValues = (obj) => {
      if (typeof obj !== 'object' || obj === null) {
        return obj; // If it's not an object, return as is
      }
  
      const encodedObj = {};
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          const encodedKey = Buffer.from(key).toString('base64');
          const value = obj[key];
          encodedObj[encodedKey] = typeof value === 'object' ? encodeKeysAndValues(value) : Buffer.from(value).toString('base64'); // Recursively encode nested objects or encode values
        }
      }
      return encodedObj;
    };
  
    let dump_data = {"data" : this.data, "secrets" : this.secrets}
    let jsonData = JSON.stringify(dump_data);

    let encoded_data = Buffer.from(jsonData,"utf-8").toString("base64")
    let enc = {"data" : encoded_data, "kvs": encodeKeysAndValues(this.data)}

    let string_enc = JSON.stringify(enc)

    let buffer_data = stringToBuffer(jsonData);
  
    // Calculate the checksum over the serialized data
    const checksum = await subtle.digest("SHA-256", buffer_data);
  
    const string_checksum = bufferToString(checksum);
  
    return [string_enc, string_checksum];
  }
  



  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // const hmac = crypto.createHmac('sha256', this.secrets["hmac_for_domain_name"]);
    // const hmac_name = hmac.update(name).digest('hex');
    if (this.data[name]) {
      return this.data[name]
    } else {
      return null
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    // const hmac1 = crypto.createHmac('sha256', this.secrets.hmac_for_domain_name);
    // const hmac_name = hmac1.update(name).digest('hex');

    // const cipher = crypto.createCipheriv('aes-256-gcm', this.secrets.aesKey, Buffer.from(this.secrets.iv, 'hex'));
    // let encrypted = cipher.update(value, 'utf8', 'hex');
    // encrypted += cipher.final('hex');

    // this.data[hmac_name] = encrypted;
    this.data[name] = value
}

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (this.data[name]) {
      delete this.data[name]
      return true
    } else {
      return false
    }
  };
};

module.exports = { Keychain }
