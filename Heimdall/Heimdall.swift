//
//  Heimdall.swift
//
//  Heimdall - The gatekeeper of Bifrost, the road connecting the 
//  world (Midgard) to Asgard, home of the Norse gods.
//
//  In iOS, Heimdall is the gatekeeper to the Keychain, offering
//  a nice wrapper for interacting with private-public RSA keys
//  and encrypting/decrypting/signing data.
//
//  Created by Henri Normak on 22/04/15.
//
//  The MIT License (MIT)
//
//  Copyright (c) 2015 Henri Normak
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

import Foundation
import Security
import CommonCrypto

public class Heimdall {
    private let publicTag: String
    private var privateTag: String?
    private var scope: ScopeOptions
    
    /// 
    /// Create an instance with data for the public key,
    /// the keychain is updated with the tag given (call .destroy() to remove)
    ///
    /// - parameters:
    ///     - publicTag: Tag of the public key, keychain is checked for existing key (updated if data
    /// provided is non-nil and does not match)
    ///     - publicKeyData: Bits of the public key, can include the X509 header (will be stripped)
    ///
    /// - returns: Heimdall instance that can handle only public key operations
    ///
    public convenience init?(publicTag: String, publicKeyData: NSData? = nil) {
        if let existingData = Heimdall.obtainKeyData(publicTag) {
            // Compare agains the new data (optional)
            if let newData = publicKeyData?.dataByStrippingX509Header() where !existingData.isEqualToData(newData) {
                Heimdall.updateKey(publicTag, data: newData)
            }
            
            self.init(scope: ScopeOptions.PublicKey, publicTag: publicTag, privateTag: nil)
        } else if let data = publicKeyData?.dataByStrippingX509Header(), _ = Heimdall.insertPublicKey(publicTag, data: data) {
            // Successfully created the new key
            self.init(scope: ScopeOptions.PublicKey, publicTag: publicTag, privateTag: nil)
        } else {
            // Call the init, although returning nil
            self.init(scope: ScopeOptions.PublicKey, publicTag: publicTag, privateTag: nil)
            return nil
        }
    }
    
    ///
    /// Create an instance with the modulus and exponent of the public key
    /// the resulting key is added to the keychain (call .destroy() to remove)
    ///
    /// - parameters:
    ///     - publicTag: Tag of the public key, see data based initialiser for details
    ///     - publicKeyModulus: Modulus of the public key
    ///     - publicKeyExponent: Exponent of the public key
    ///
    /// - returns: Heimdall instance that can handle only public key operations
    ///
    public convenience init?(publicTag: String, publicKeyModulus: NSData, publicKeyExponent: NSData) {
        // Combine the data into one that we can use for initialisation
        let combinedData = NSData(modulus: publicKeyModulus, exponent: publicKeyExponent)
        self.init(publicTag: publicTag, publicKeyData: combinedData)
    }
    
    ///
    /// Shorthand for creating an instance with both public and private key, where the tag
    /// for private key is automatically generated
    ///
    /// - parameters
    ///     - tagPrefix: Prefix to use for the private/public keys in Keychain
    ///     - keySize: Size of the RSA key pair
    ///
    /// - returns: Heimdall instance that can handle both private and public key operations
    ///
    public convenience init?(tagPrefix: String, keySize: Int = 2048) {
        self.init(publicTag: tagPrefix, privateTag: tagPrefix + ".private", keySize: keySize)
    }
    
    ///
    /// Create an instane with public and private key tags, if the key pair does not exist
    /// the keys will be generated
    ///
    /// - parameters:
    ///     - publicTag: Tag to use for the public key
    ///     - privateTag: Tag to use for the private key
    ///     - keySize: Size of the RSA key pair
    ///
    /// - returns: Heimdall instance ready for both public and private key operations
    ///
    public convenience init?(publicTag: String, privateTag: String, keySize: Int = 2048) {
        self.init(scope: ScopeOptions.All, publicTag: publicTag, privateTag: privateTag)

        if Heimdall.obtainKey(publicTag) == nil || Heimdall.obtainKey(privateTag) == nil {
            if Heimdall.generateKeyPair(publicTag, privateTag: privateTag, keySize: keySize) == nil {
                return nil
            }
        }
    }
    
    private init(scope: ScopeOptions, publicTag: String, privateTag: String?) {
        self.publicTag = publicTag
        self.privateTag = privateTag
        self.scope = scope
    }
    
    //
    //  MARK: Public functions
    //
    
    ///
    /// - returns: Public key in X.509 format
    ///
    public func publicKeyDataX509() -> NSData? {
        if let keyData = obtainKeyData(.Public) {
            return keyData.dataByPrependingX509Header()
        }
        
        return nil
    }
    
    ///
    /// - returns: Public key components (modulus and exponent)
    ///
    public func publicKeyComponents() -> (modulus: NSData, exponent: NSData)? {
        if let keyData = obtainKeyData(.Public), (modulus, exponent) = keyData.splitIntoComponents() {
            return (modulus, exponent)
        }
        
        return nil
    }
    
    ///
    /// - returns: Public key data
    ///
    public func publicKeyData() -> NSData? {
        return obtainKeyData(.Public)
    }
    
    ///
    /// Encrypt an arbitrary string using AES256, the key for which
    /// is generated for a particular process and then encrypted with the
    /// public key from the RSA pair and prepended to the resulting data
    ///
    /// - parameters:
    ///     - string: Input string to be encrypted
    ///     - urlEncode: If true, resulting Base64 string is URL encoded
    ///
    /// - returns: The encrypted data, as Base64 string
    ///
    public func encrypt(string: String, urlEncode: Bool = false) -> String? {
        if let data = string.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false), encrypted = self.encrypt(data) {
            
            // Convert to a string
            var resultString = encrypted.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
            
            if urlEncode {
                resultString = resultString.stringByReplacingOccurrencesOfString("/", withString: "_")
                resultString = resultString.stringByReplacingOccurrencesOfString("+", withString: "-")
            }
            
            return resultString
        }
        
        return nil
    }
    
    ///
    /// Encrypt an arbitrary message using AES256, the key for which
    /// is generated for a particular process and then encrypted with the
    /// public key from the RSA pair and prepended to the resulting data
    ///
    /// - parameters:
    ///     - data: Input data to be encrypted
    ///
    /// - returns: The encrypted data
    ///
    public func encrypt(data: NSData) -> NSData? {
        if let publicKey = obtainKey(.Public) {
            // Determine appropriate AES key size
            let blockSize = SecKeyGetBlockSize(publicKey)
            let keySize: Int
            if blockSize >= 256 {
                keySize = Int(kCCKeySizeAES256)
            } else if blockSize >= 192 {
                keySize = Int(kCCKeySizeAES192)
            } else {
                keySize = Int(kCCKeySizeAES128)
            }
            
            if let aesKey = Heimdall.generateSymmetricKey(keySize), encrypted = Heimdall.encrypt(data, key: aesKey, algorithm: CCAlgorithm(kCCAlgorithmAES128)) {
                // Final resulting data
                let result = NSMutableData()
                
                // Encrypt the AES key with our public key
                var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
                var encryptedLength = blockSize
                let data = UnsafePointer<UInt8>(aesKey.bytes)
                
                switch SecKeyEncrypt(publicKey, .PKCS1, data, Int(aesKey.length), &encryptedData, &encryptedLength) {
                case noErr:
                    result.appendBytes(&encryptedData, length: encryptedLength)
                default:
                    return nil
                }
                
                result.appendData(encrypted)
                
                return result
            }
        }
        
        return nil
    }
    
    ///
    /// Decrypt a Base64 string representation of encrypted data
    ///
    /// - parameters:
    ///     - base64String: String containing Base64 data to decrypt
    ///     - urlEncoded: Whether the input Base64 data is URL encoded
    ///
    /// - returns: Decrypted string as plain text
    ///
    public func decrypt(var base64String: String, urlEncoded: Bool = true) -> String? {
        if urlEncoded {
            base64String = base64String.stringByReplacingOccurrencesOfString("_", withString: "/")
            base64String = base64String.stringByReplacingOccurrencesOfString("-", withString: "+")
        }
        
        if let data = NSData(base64EncodedString: base64String, options: NSDataBase64DecodingOptions(rawValue: 0)), decryptedData = self.decrypt(data) {
            return NSString(data: decryptedData, encoding: NSUTF8StringEncoding) as? String
        }
        
        return nil
    }
    
    ///
    /// Decrypt the encrypted data
    ///
    /// - parameters:
    ///     - encryptedData: Data to decrypt
    ///
    /// - returns: The decrypted data, or nil if failed
    ///
    public func decrypt(encryptedData: NSData) -> NSData? {
        if let key = obtainKey(.Private) {
            // First block size should be the encrypted AES key
            let blockSize = SecKeyGetBlockSize(key)
            let keyData = encryptedData.subdataWithRange(NSRange(location: 0, length: blockSize))
            let messageData = encryptedData.subdataWithRange(NSRange(location: blockSize, length: encryptedData.length - blockSize))
            
            // Decrypt the key
            if let decryptedKey = NSMutableData(length: blockSize) {
                let encryptedKeyData = UnsafePointer<UInt8>(keyData.bytes)
                let decryptedKeyData = UnsafeMutablePointer<UInt8>(decryptedKey.mutableBytes)
                var decryptedLength = blockSize
                
                let keyStatus = SecKeyDecrypt(key, .PKCS1, encryptedKeyData, keyData.length, decryptedKeyData, &decryptedLength)
                
                if keyStatus == noErr {
                    decryptedKey.length = Int(decryptedLength)
                    
                    // Decrypt the message
                    if let message = Heimdall.decrypt(messageData, key: decryptedKey, algorithm: CCAlgorithm(kCCAlgorithmAES128)) {
                        return message
                    }
                }
            }
        }
        
        return nil
    }
    
    ///
    /// Generate a signature for an arbitrary message
    ///
    /// - parameters:
    ///     - string: Message to generate the signature for
    ///     - urlEncode: True if the resulting Base64 data should be URL encoded
    ///
    /// - returns: Signature as a Base64 string
    ///
    public func sign(string: String, urlEncode: Bool = false) -> String? {
        if let data = string.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false), signatureData = self.sign(data) {
            
            var signature = signatureData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
            
            if urlEncode {
                signature = signature.stringByReplacingOccurrencesOfString("/", withString: "_")
                signature = signature.stringByReplacingOccurrencesOfString("+", withString: "-")
            }
            
            return signature
        }
        
        return nil
    }
    
    ///
    /// Generate a signature for an arbitrary payload
    ///
    /// - parameters:
    ///     - data: Data to sign
    ///
    /// - returns: Signature as NSData
    ///
    public func sign(data: NSData) -> NSData? {
        if let key = obtainKey(.Private), hash = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) {
            
            // Create SHA256 hash of the message
            CC_SHA256(data.bytes, CC_LONG(data.length), UnsafeMutablePointer(hash.mutableBytes))
            
            // Sign the hash with the private key
            let blockSize = SecKeyGetBlockSize(key)
            
            let hashDataLength = Int(hash.length)
            let hashData = UnsafePointer<UInt8>(hash.bytes)
            
            if let result = NSMutableData(length: Int(blockSize)) {
                let encryptedData = UnsafeMutablePointer<UInt8>(result.mutableBytes)
                var encryptedDataLength = blockSize
                
                let status = SecKeyRawSign(key, .PKCS1SHA256, hashData, hashDataLength, encryptedData, &encryptedDataLength)
                
                if status == noErr {
                    // Create Base64 string of the result
                    result.length = encryptedDataLength
                    return result
                }
            }
        }
        
        return nil
    }
    
    
    ///
    /// Verify the message with the given signature
    ///
    /// - parameters:
    ///     - message: Message that was used to generate the signature
    ///     - signatureBase64: Base64 of the signature data, signature is made of the SHA256 hash of message
    ///     - urlEncoded: True, if the signature is URL encoded and has to be reversed before manipulating
    ///
    /// - returns: true if the signature is valid (and can be validated)
    ///
    public func verify(message: String, var signatureBase64: String, urlEncoded: Bool = true) -> Bool {
        if urlEncoded {
            signatureBase64 = signatureBase64.stringByReplacingOccurrencesOfString("_", withString: "/")
            signatureBase64 = signatureBase64.stringByReplacingOccurrencesOfString("-", withString: "+")
        }

        if let data = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false), signature = NSData(base64EncodedString: signatureBase64, options: NSDataBase64DecodingOptions(rawValue: 0)) {
            return self.verify(data, signatureData: signature)
        }
        
        return false
    }
    
    ///
    /// Verify a data payload with the given signature
    ///
    /// - parameters:
    ///     - data: Data the signature should be verified against
    ///     - signatureData: Data of the signature
    ///
    /// - returns: True if the signature is valid
    ///
    public func verify(data: NSData, signatureData: NSData) -> Bool {
        if let key = obtainKey(.Public), hashData = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) {
            CC_SHA256(data.bytes, CC_LONG(data.length), UnsafeMutablePointer(hashData.mutableBytes))
            
            let signedData = UnsafePointer<UInt8>(hashData.bytes)
            let signatureLength = Int(signatureData.length)
            let signatureData = UnsafePointer<UInt8>(signatureData.bytes)
            
            let result = SecKeyRawVerify(key, .PKCS1SHA256, signedData, Int(CC_SHA256_DIGEST_LENGTH), signatureData, signatureLength)
            
            switch result {
            case noErr:
                return true
            default:
                return false
            }
        }
        
        return false
    }
    
    // MARK: Managing the key pair
    
    ///
    /// Remove the key pair this Heimdall represents
    /// Does not regenerate the keys, thus the Heimdall
    /// instance becomes useless after this call
    ///
    /// - returns: True if remove successfully
    ///
    public func destroy() -> Bool {
        if Heimdall.deleteKey(self.publicTag) {
            self.scope = self.scope & ~(ScopeOptions.PublicKey)
            
            if let privateTag = self.privateTag where Heimdall.deleteKey(privateTag) {
                self.scope = self.scope & ~(ScopeOptions.PrivateKey)
                return true
            }
            
            return true
        }
        
        return false
    }
    
    ///
    /// Delete existing key pair and regenerate new one
    /// This will always fail for instances that don't have
    /// a private key, including those that have been explicitly
    /// destroyed beforehand
    ///
    /// - parameters:
    ///     - keySize: Size of keys in the new pair
    ///
    /// - returns: True if reset successfully
    ///
    public func regenerate(keySize: Int = 2048) -> Bool {
        // Only if we currently have a private key in our control (or we think we have one)
        if self.scope & ScopeOptions.PrivateKey != ScopeOptions.PrivateKey {
            return false
        }
        
        if let privateTag = self.privateTag where self.destroy() {
            if Heimdall.generateKeyPair(self.publicTag, privateTag: privateTag, keySize: keySize) != nil {
                // Restore our scope back to .All
                self.scope = .All
                return true
            }
        }
        
        return false
    }
    
    //
    //  MARK: Private types
    //
    private enum KeyType {
        case Public
        case Private
    }
    
    private struct ScopeOptions: OptionSetType {
        private var value: UInt
        
        init(_ rawValue: UInt) { self.value = rawValue }
        init(rawValue: UInt) { self.value = rawValue }
        init(nilLiteral: ()) { self.value = 0}
        
        var rawValue: UInt { return self.value }
        var boolValue: Bool { return self.value != 0 }
        
        static var allZeros: ScopeOptions { return self.init(0) }
        
        static var PublicKey: ScopeOptions { return self.init(1 << 0) }
        static var PrivateKey: ScopeOptions { return self.init(1 << 1) }
        static var All: ScopeOptions           { return self.init(0b11) }
    }
    
    
    //
    //  MARK: Private helpers
    //
    private func obtainKey(key: KeyType) -> SecKeyRef? {
        if key == .Public && self.scope & ScopeOptions.PublicKey == ScopeOptions.PublicKey {
            return Heimdall.obtainKey(self.publicTag)
        } else if let tag = self.privateTag where key == .Private && self.scope & ScopeOptions.PrivateKey == ScopeOptions.PrivateKey {
            return Heimdall.obtainKey(tag)
        }
        
        return nil
    }
    
    private func obtainKeyData(key: KeyType) -> NSData? {
        if key == .Public && self.scope & ScopeOptions.PublicKey == ScopeOptions.PublicKey {
            return Heimdall.obtainKeyData(self.publicTag)
        } else if let tag = self.privateTag where key == .Private && self.scope & ScopeOptions.PrivateKey == ScopeOptions.PrivateKey {
            return Heimdall.obtainKeyData(tag)
        }
        
        return nil
    }
    
    //
    //  MARK: Private class functions
    //
    
    private class func obtainKey(tag: String) -> SecKeyRef? {
        var keyRef: AnyObject?
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnRef): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
        ]
        
        let status = SecItemCopyMatching(query, &keyRef)
        
        switch status {
        case noErr:
            if let ref = keyRef {
                return (ref as! SecKeyRef)
            }
        default:
            break
        }
        
        return nil
    }
    
    private class func obtainKeyData(tag: String) -> NSData? {
        var keyRef: AnyObject?
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
        ]
        
        let result: NSData?
        
        switch SecItemCopyMatching(query, &keyRef) {
        case noErr:
            result = keyRef as? NSData
        default:
            result = nil
        }
        
        return result
    }
    
    private class func updateKey(tag: String, data: NSData) -> Bool {
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef]
        
        return SecItemUpdate(query, [String(kSecValueData): data]) == noErr
    }
    
    private class func deleteKey(tag: String) -> Bool {
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef]
        
        return SecItemDelete(query) == noErr
    }
    
    private class func insertPublicKey(publicTag: String, data: NSData) -> SecKeyRef? {
        var publicAttributes = Dictionary<String, AnyObject>()
        publicAttributes[String(kSecAttrKeyType)] = kSecAttrKeyTypeRSA
        publicAttributes[String(kSecClass)] = kSecClassKey as CFStringRef
        publicAttributes[String(kSecAttrApplicationTag)] = publicTag as CFStringRef
        publicAttributes[String(kSecValueData)] = data as CFDataRef
        publicAttributes[String(kSecReturnPersistentRef)] = true as CFBooleanRef
        
        var persistentRef: AnyObject?
        let status = SecItemAdd(publicAttributes, &persistentRef)
        
        if status != noErr && status != errSecDuplicateItem {
            return nil
        }
        
        return Heimdall.obtainKey(publicTag)
    }
    
    
    private class func generateKeyPair(publicTag: String, privateTag: String, keySize: Int) -> (publicKey: SecKeyRef, privateKey: SecKeyRef)? {
        let privateAttributes = [String(kSecAttrIsPermanent): true,
                                 String(kSecAttrApplicationTag): privateTag]
        let publicAttributes = [String(kSecAttrIsPermanent): true,
                                String(kSecAttrApplicationTag): publicTag]
        
        let pairAttributes = [String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
                              String(kSecAttrKeySizeInBits): keySize,
                              String(kSecPublicKeyAttrs): publicAttributes,
                              String(kSecPrivateKeyAttrs): privateAttributes]
        
        var publicRef: SecKey?
        var privateRef: SecKey?
        switch SecKeyGeneratePair(pairAttributes, &publicRef, &privateRef) {
            case noErr:
                if let publicKey = publicRef, privateKey = privateRef {
                    return (publicKey, privateKey)
                }
                
                return nil
            default:
                return nil
        }
    }
    
    private class func generateSymmetricKey(keySize: Int) -> NSData? {
        var result = [UInt8](count: keySize, repeatedValue: 0)
        SecRandomCopyBytes(kSecRandomDefault, keySize, &result)
        
        return NSData(bytes: result, length: keySize)
    }
    
    
    private class func encrypt(data: NSData, key: NSData, algorithm: CCAlgorithm) -> NSData? {
        let dataBytes = UnsafePointer<UInt8>(data.bytes)
        let dataLength = data.length
        
        if let result = NSMutableData(length: dataLength + key.length) {
            let keyData = UnsafePointer<UInt8>(key.bytes)
            let keyLength = size_t(key.length)
            
            let encryptedData = UnsafeMutablePointer<UInt8>(result.mutableBytes)
            let encryptedDataLength = size_t(result.length)
            
            var encryptedLength: size_t = 0
            
            let status = CCCrypt(CCOperation(kCCEncrypt), algorithm, CCOptions(kCCOptionPKCS7Padding), keyData, keyLength, nil, dataBytes, dataLength, encryptedData, encryptedDataLength, &encryptedLength)
            
            if UInt32(status) == UInt32(kCCSuccess) {
                result.length = Int(encryptedLength)
                return result
            }
        }
        
        return nil
    }
    
    private class func decrypt(data: NSData, key: NSData, algorithm: CCAlgorithm) -> NSData? {
        let encryptedData = UnsafePointer<UInt8>(data.bytes)
        let encryptedDataLength = data.length
        
        if let result = NSMutableData(length: encryptedDataLength) {
            let keyData = UnsafePointer<UInt8>(key.bytes)
            let keyLength = size_t(key.length)
            
            let decryptedData = UnsafeMutablePointer<UInt8>(result.mutableBytes)
            let decryptedDataLength = size_t(result.length)
            
            var decryptedLength: size_t = 0
            
            let status = CCCrypt(CCOperation(kCCDecrypt), algorithm, CCOptions(kCCOptionPKCS7Padding), keyData, keyLength, nil, encryptedData, encryptedDataLength, decryptedData, decryptedDataLength, &decryptedLength)
            
            if UInt32(status) == UInt32(kCCSuccess) {
                result.length = Int(decryptedLength)
                return result
            }
        }

        return nil
    }
}

///
/// Arithmetic
///

private func ==(lhs: Heimdall.ScopeOptions, rhs: Heimdall.ScopeOptions) -> Bool {
    return lhs.rawValue == rhs.rawValue
}

private prefix func ~(op: Heimdall.ScopeOptions) -> Heimdall.ScopeOptions {
    return Heimdall.ScopeOptions(~op.rawValue)
}

private func &(lhs: Heimdall.ScopeOptions, rhs: Heimdall.ScopeOptions) -> Heimdall.ScopeOptions {
    return Heimdall.ScopeOptions(lhs.rawValue & rhs.rawValue)
}

///
/// Encoding/Decoding lengths as octets
///
private extension NSInteger {
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)];
        }
        
        // Long form
        let i = (self / 256) + 1
        var len = self
        var result: [CUnsignedChar] = [CUnsignedChar(i + 0x80)]
        
        for (var j = 0; j < i; j++) {
            result.insert(CUnsignedChar(len & 0xFF), atIndex: 1)
            len = len >> 8
        }
        
        return result
    }
    
    init?(octetBytes: [CUnsignedChar], inout startIdx: NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] - 128)
            
            if octets > octetBytes.count - startIdx {
                self.init(0)
                return nil
            }
            
            var result = UInt64(0)
            
            for j in 1...octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIdx + j])
            }
            
            startIdx += 1 + octets
            self.init(result)
        }
    }
}


///
/// Manipulating data
///
private extension NSData {
    convenience init(modulus: NSData, exponent: NSData) {
        // Make sure neither the modulus nor the exponent start with a null byte
        var modulusBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(modulus.bytes), count: modulus.length / sizeof(CUnsignedChar)))
        let exponentBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(exponent.bytes), count: exponent.length / sizeof(CUnsignedChar)))
        
        // Make sure modulus starts with a 0x00
        if let prefix = modulusBytes.first where prefix != 0x00 {
            modulusBytes.insert(0x00, atIndex: 0)
        }
        
        // Lengths
        let modulusLengthOctets = modulusBytes.count.encodedOctets()
        let exponentLengthOctets = exponentBytes.count.encodedOctets()
        
        // Total length is the sum of components + types
        let totalLengthOctets = (modulusLengthOctets.count + modulusBytes.count + exponentLengthOctets.count + exponentBytes.count + 2).encodedOctets()
        
        // Combine the two sets of data into a single container
        var builder: [CUnsignedChar] = []
        let data = NSMutableData()
        
        // Container type and size
        builder.append(0x30)
        builder.appendContentsOf(totalLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)
        
        // Modulus
        builder.append(0x02)
        builder.appendContentsOf(modulusLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)
        data.appendBytes(modulusBytes, length: modulusBytes.count)
        
        // Exponent
        builder.append(0x02)
        builder.appendContentsOf(exponentLengthOctets)
        data.appendBytes(builder, length: builder.count)
        data.appendBytes(exponentBytes, length: exponentBytes.count)
        
        self.init(data: data)
    }
    
    func splitIntoComponents() -> (modulus: NSData, exponent: NSData)? {
        // Get the bytes from the keyData
        let pointer = UnsafePointer<CUnsignedChar>(self.bytes)
        let keyBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start:pointer, count:self.length / sizeof(CUnsignedChar)))

        // Assumption is that the data is in DER encoding
        // If we can parse it, then return successfully
        var i: NSInteger = 0
        
        // First there should be an ASN.1 SEQUENCE
        if keyBytes[0] != 0x30 {
            return nil
        } else {
            i += 1
        }

        // Total length of the container
        if let _ = NSInteger(octetBytes: keyBytes, startIdx: &i) {
            // First component is the modulus
            if keyBytes[i++] == 0x02, let modulusLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                let modulus = self.subdataWithRange(NSMakeRange(i, modulusLength))
                i += modulusLength
                
                // Second should be the exponent
                if keyBytes[i++] == 0x02, let exponentLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                    let exponent = self.subdataWithRange(NSMakeRange(i, exponentLength))
                    i += exponentLength
                    
                    return (modulus, exponent)
                }
            }
        }
        
        return nil
    }
    
    func dataByPrependingX509Header() -> NSData {
        let result = NSMutableData()
        
        let encodingLength: Int = (self.length + 1).encodedOctets().count
        let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
        
        var builder: [CUnsignedChar] = []
        
        // ASN.1 SEQUENCE
        builder.append(0x30)
        
        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.length
        let encodedSize = size.encodedOctets()
        builder.appendContentsOf(encodedSize)
        result.appendBytes(builder, length: builder.count)
        result.appendBytes(OID, length: OID.count)
        builder.removeAll(keepCapacity: false)
        
        builder.append(0x03)
        builder.appendContentsOf((self.length + 1).encodedOctets())
        builder.append(0x00)
        result.appendBytes(builder, length: builder.count)
        
        // Actual key bytes
        result.appendData(self)
        
        return result as NSData
    }
    
    func dataByStrippingX509Header() -> NSData {
        var bytes = [CUnsignedChar](count: self.length, repeatedValue: 0)
        self.getBytes(&bytes, length:self.length)
        
        var range = NSRange(location: 0, length: self.length)
        var offset = 0
        
        // ASN.1 Sequence
        if bytes[offset++] == 0x30 {
            // Skip over length
            let _ = NSInteger(octetBytes: bytes, startIdx: &offset)
            
            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let slice: [CUnsignedChar] = Array(bytes[offset..<(offset + OID.count)])
            
            if slice == OID {
                offset += OID.count
                
                // Type
                if bytes[offset++] != 0x03 {
                    return self
                }
                
                // Skip over the contents length field
                let _ = NSInteger(octetBytes: bytes, startIdx: &offset)
                
                // Contents should be separated by a null from the header
                if bytes[offset++] != 0x00 {
                    return self
                }
                
                range.location += offset
                range.length -= offset
            } else {
                return self
            }
        }
        
        return self.subdataWithRange(range)
    }
}

