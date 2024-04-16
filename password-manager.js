"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const { crypto } = require('crypto');

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
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
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
    return new Promise((resolve, reject) => {
        const salt = getRandomBytes(16);
        crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, 64, 'sha512', (err, key) => {
            if (err) {
                reject(err);
                return;
            }
            const key_for_hmac = key.toString('base64');
            const buffer_key_for_hmac = stringToBuffer(key_for_hmac);
            const hmac = crypto.createHmac('sha512', buffer_key_for_hmac);
            const subKeyForMac = hmac.update('MAC domain names').digest();
            const subKeyForEncrypt = hmac.update('Encrypt passwords').digest();
            
            const keychain = new Keychain();
            keychain.data = {};
            keychain.secrets = {
                master_password: password,
                key_for_hmac: key_for_hmac,
                buffer_key_for_hmac: buffer_key_for_hmac,
                hmac_value: hmac,
                subkey_for_mac_domain: subKeyForMac,
                subkey_for_encrypting_password: subKeyForEncrypt
            };
            resolve(keychain);
        });
    });
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
  static async load(password, repr, checksum) {
    const [checkJson, _] = this.dump();
    if (repr === checkJson) {
      try {
        if (password === this.secrets.master_password) {
          return this.init(password);
        }
      } catch (error) {
        throw "chiu roi man";
      }
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
    const serializedData = JSON.stringify({ data: this.data, secrets: this.secrets });
    const hash = await crypto.createHash('sha256').update(serializedData).digest('hex');
    return [serializedData, hash];
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
    const hmac = crypto.createHmac('sha256', this.secrets.subkey_for_mac_domain);
    const mac_domain_name = hmac.update(name).digest('hex');
    const encrypted_pw = this.data[mac_domain_name];
    if (encrypted_pw) {
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.secrets.subkey_for_encrypting_password, stringToBuffer(encrypted_pw));
      let decrypted = decipher.update(encrypted_pw.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } else {
      return null;
    }
  }

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
    const hmac = crypto.createHmac('sha256', this.secrets.subkey_for_mac_domain);
    const mac_domain_name = hmac.update(name).digest('hex');
    const cipher = crypto.createCipheriv('aes-256-gcm', this.secrets.subkey_for_encrypting_password);
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    this.data[mac_domain_name] = encrypted;
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
    const hmac = crypto.createHmac('sha256', this.secrets.subkey_for_mac_domain);
    const mac_domain_name = hmac.update(name).digest('hex');
    if (this.data[mac_domain_name]) {
      delete this.data[mac_domain_name];
      return true;
    } else {
      return false;
    }
  }
}

module.exports = { Keychain }
