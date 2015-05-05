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
    private let privateTag: String?
    private let keySize: Int
    private let scope: ScopeOptions
    
    /// 
    /// Create an instance with data for the public key,
    /// the keychain is updated with the tag given (call .destroy() to remove)
    ///
    /// :params: publicTag      Tag of the public key, keychain is checked for existing key (updated if data 
    /// provided is non-nil and does not match)
    ///
    /// :params: publicKeyData  Bits of the public key, can include the X509 header (will be stripped)
    ///
    /// :returns: Heimdall instance that can handle only public key operations
    ///
    public convenience init?(publicTag: String, var publicKeyData: NSData? = nil) {
        if let existingData = Heimdall.obtainKeyData(publicTag) {
            var keySize = existingData.length * 8
            
            // Compare agains the new data (optional)
            if let newData = publicKeyData?.dataByStrippingX509Header() where !existingData.isEqualToData(newData) {
                Heimdall.updateKey(publicTag, keySize: nil, data: newData)
                keySize = newData.length * 8
            }
            
            self.init(scope: ScopeOptions.PublicKey, publicTag: publicTag, privateTag: nil, keySize: keySize)
        } else if let data = publicKeyData?.dataByStrippingX509Header(), key = Heimdall.insertPublicKey(publicTag, data: data) {
            // Successfully created the new key
            self.init(scope: ScopeOptions.PublicKey, publicTag: publicTag, privateTag: nil, keySize: data.length * 8)
        } else {
            // Call the init, although returning nil
            self.init(scope: ScopeOptions.PublicKey, publicTag: publicTag, privateTag: nil, keySize: 0)
            return nil
        }
    }
    
    ///
    /// Shorthand for creating an instance with both public and private key, where the tag
    /// for private key is automatically generated
    ///
    /// :returns: Heimdall instance that can handle both private and public key operations
    ///
    public convenience init?(tagPrefix: String, keySize: Int = 2048) {
        self.init(publicTag: tagPrefix, privateTag: tagPrefix + ".private", keySize: keySize)
    }
    
    ///
    /// Create an instane with public and private key tags, if the key pair does not exist
    /// the keys will be generated
    ///
    /// :returns: Heimdall instance ready for both public and private key operations
    ///
    public convenience init?(publicTag: String, privateTag: String, keySize: Int = 2048) {
        self.init(scope: ScopeOptions.All, publicTag: publicTag, privateTag: privateTag, keySize: keySize)

        if Heimdall.obtainKey(publicTag, keySize: keySize) == nil || Heimdall.obtainKey(privateTag, keySize: keySize) == nil {
            if Heimdall.generateKeyPair(publicTag, privateTag: privateTag, keySize: keySize) == nil {
                return nil
            }
        }
    }
    
    private init(scope: ScopeOptions, publicTag: String, privateTag: String?, keySize: Int) {
        self.publicTag = publicTag
        self.privateTag = privateTag
        self.keySize = keySize
        self.scope = scope
    }
    
    //
    //  MARK: Public functions
    //
    
    ///
    /// :returns: Public key in X.509 format
    ///
    public func X509PublicKey() -> NSData? {
        if let key = obtainKeyData(.Public) {
            return key.dataByPrependingX509Header()
        }
        
        return nil
    }
    
    ///
    /// Encrypt an arbitrary string using AES256, the key for which
    /// is generated for a particular process and then encrypted with the
    /// public key from the RSA pair and prepended to the resulting data
    ///
    /// Result is a combination, where the first
    /// Encrypt an arbitrary string using the public key of the pair
    ///
    /// :param: string      Input string to be encrypted
    /// :param: urlEncode   If true, resulting Base64 string is URL encoded
    ///
    /// :returns: The encrypted data, as Base64 string. First
    ///
    public func encrypt(string: String, urlEncode: Bool = false) -> String? {
        // Generate a key and encrypt the message with said key
        if let publicKey = obtainKey(.Public), aesKey = Heimdall.generateSymmetricKey(Int(kCCKeySizeAES256)), encrypted = Heimdall.encrypt(string, key: aesKey) {
            // Final resulting data
            let result = NSMutableData()
            
            // Encrypt the AES key with our public key
            let blockSize = SecKeyGetBlockSize(publicKey)
            var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
            var encryptedLength = blockSize
            var data = UnsafePointer<UInt8>(aesKey.bytes)
            
            switch SecKeyEncrypt(publicKey, SecPadding(kSecPaddingPKCS1), data, Int(aesKey.length), &encryptedData, &encryptedLength) {
            case noErr:
                result.appendBytes(&encryptedData, length: encryptedLength)
            default:
                return nil
            }
            
            result.appendData(encrypted)
            
            // Convert to a string
            var resultString = result.base64EncodedStringWithOptions(.allZeros)
            
            if urlEncode {
                resultString = resultString.stringByReplacingOccurrencesOfString("/", withString: "_")
                resultString = resultString.stringByReplacingOccurrencesOfString("+", withString: "-")
            }
            
            return resultString
        }
        
        return nil
    }
    
    ///
    /// Decrypt a Base64 string representation of encrypted data
    ///
    /// :param: base64String    string containing Base64 data to decrypt
    /// :param: urlEncoded      whether the input Base64 data is URL encoded (if true, some additional changes need to be made first)
    ///
    /// :returns: Decrypted string as plain text
    ///
    public func decrypt(var base64String: String, urlEncoded: Bool = true) -> String? {
        if let key = obtainKey(.Private) {
            if urlEncoded {
                base64String = base64String.stringByReplacingOccurrencesOfString("_", withString: "/")
                base64String = base64String.stringByReplacingOccurrencesOfString("-", withString: "+")
            }
            
            // Convert to data and grab our private key
            if let data = NSData(base64EncodedString: base64String, options: .allZeros) {
                // First block size should be the encrypted AES key
                let blockSize = SecKeyGetBlockSize(key)
                let keyData = data.subdataWithRange(NSRange(location: 0, length: blockSize))
                let messageData = data.subdataWithRange(NSRange(location: blockSize, length: data.length - blockSize))
                
                // Decrypt the key
                if let decryptedKeyData = NSMutableData(length: blockSize) {
                    let encryptedData = UnsafePointer<UInt8>(keyData.bytes)
                    var decryptedData = UnsafeMutablePointer<UInt8>(decryptedKeyData.mutableBytes)
                    var decryptedLength = blockSize
                    
                    let keyStatus = SecKeyDecrypt(key, SecPadding(kSecPaddingPKCS1), encryptedData, keyData.length, decryptedData, &decryptedLength)
                    
                    if keyStatus == noErr {
                        decryptedKeyData.length = Int(decryptedLength)
                        
                        // Decrypt the message
                        if let message = Heimdall.decrypt(messageData, key: decryptedKeyData) {
                            return NSString(data: message, encoding: NSUTF8StringEncoding) as? String
                        }
                    }
                }
            }
        }
        
        return nil
    }
    
    ///
    /// Generate a signature for an arbitrary message
    ///
    /// :param: message     Message to generate the signature for
    /// :param: urlEncode   True if the resulting Base64 data should be URL encoded
    ///
    /// :returns: Signature as a Bas64 string
    ///
    public func sign(message: String, urlEncode: Bool = false) -> String? {
        if let key = obtainKey(.Private), messageData = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false), hash = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) {
            
            // Create SHA256 hash of the message
            CC_SHA256(messageData.bytes, CC_LONG(messageData.length), UnsafeMutablePointer(hash.mutableBytes))
            
            // Sign the hash with the private key
            let blockSize = SecKeyGetBlockSize(key)
            
            let hashDataLength = Int(hash.length)
            let hashData = UnsafePointer<UInt8>(hash.bytes)
            
            if let result = NSMutableData(length: Int(blockSize)) {
                let encryptedData = UnsafeMutablePointer<UInt8>(result.mutableBytes)
                var encryptedDataLength = blockSize
                
                let status = SecKeyRawSign(key, SecPadding(kSecPaddingPKCS1), hashData, hashDataLength, encryptedData, &encryptedDataLength)
                
                if status == noErr {
                    // Create Base64 string of the result
                    result.length = encryptedDataLength
                    var signature = result.base64EncodedStringWithOptions(.allZeros)
                    
                    if urlEncode {
                        signature = signature.stringByReplacingOccurrencesOfString("/", withString: "_")
                        signature = signature.stringByReplacingOccurrencesOfString("+", withString: "-")
                    }
                    
                    return signature
                }
            }
        }
        
        return nil
    }
    
    ///
    /// Verify the message with the given signature
    ///
    /// :param: message             Message that was used to generate the signature
    /// :param: signatureBase64     Base64 of the signature data, signature is made of the SHA256 hash of message
    /// :param: urlEncoded          True, if the signature is URL encoded and has to be reversed before manipulating
    ///
    /// :returns: true if the signature is valid (and can be validated)
    ///
    public func verify(message: String, var signatureBase64: String, urlEncoded: Bool = true) -> Bool {
        if let key = obtainKey(.Public) {
            if urlEncoded {
                signatureBase64 = signatureBase64.stringByReplacingOccurrencesOfString("_", withString: "/")
                signatureBase64 = signatureBase64.stringByReplacingOccurrencesOfString("-", withString: "+")
            }
            
            if let signature = NSData(base64EncodedString: signatureBase64, options: .allZeros),
                messageData = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false),
                hashData = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) {
                    
                CC_SHA256(messageData.bytes, CC_LONG(messageData.length), UnsafeMutablePointer(hashData.mutableBytes))
                
                let signedData = UnsafePointer<UInt8>(hashData.bytes)
                let signatureLength = Int(signature.length)
                let signatureData = UnsafePointer<UInt8>(signature.bytes)
                
                let result = SecKeyRawVerify(key, SecPadding(kSecPaddingPKCS1), signedData, Int(CC_SHA256_DIGEST_LENGTH), signatureData, signatureLength)
                
                switch result {
                case noErr:
                    return true
                default:
                    return false
                }
            }
        }
        
        return false
    }
    
    ///
    /// Remove the key pair this Heimdall represents
    ///
    /// :returns: True if remove successfully
    ///
    public func destroy() -> Bool {
        if Heimdall.deleteKey(self.publicTag, keySize: self.keySize) {
            if let privateTag = self.privateTag {
                return Heimdall.deleteKey(privateTag, keySize: self.keySize)
            }
            
            return true
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
    
    private struct ScopeOptions: RawOptionSetType {
        private var value: UInt
        
        init(_ rawValue: UInt) { self.value = rawValue }
        init(rawValue: UInt) { self.value = rawValue }
        init(nilLiteral: ()) { self.value = 0}
        
        var rawValue: UInt { return self.value }
        var boolValue: Bool { return self.value != 0 }
        
        static var allZeros: ScopeOptions { return self(0) }
        
        static var PublicKey: ScopeOptions { return self(1 << 0) }
        static var PrivateKey: ScopeOptions { return self(1 << 1) }
        static var All: ScopeOptions           { return self(0b11) }
    }
    
    
    //
    //  MARK: Private helpers
    //
    private func obtainKey(key: KeyType) -> SecKeyRef? {
        if key == .Public && self.scope & ScopeOptions.PublicKey == ScopeOptions.PublicKey {
            return Heimdall.obtainKey(self.publicTag, keySize: self.keySize)
        } else if let tag = self.privateTag where key == .Private && self.scope & ScopeOptions.PrivateKey == ScopeOptions.PrivateKey {
            return Heimdall.obtainKey(tag, keySize: self.keySize)
        }
        
        return nil
    }
    
    private func obtainKeyData(key: KeyType) -> NSData? {
        if key == .Public && self.scope & ScopeOptions.PublicKey == ScopeOptions.PublicKey {
            return Heimdall.obtainKeyData(self.publicTag, keySize: self.keySize)
        } else if let tag = self.privateTag where key == .Private && self.scope & ScopeOptions.PrivateKey == ScopeOptions.PrivateKey {
            return Heimdall.obtainKeyData(tag, keySize: self.keySize)
        }
        
        return nil
    }
    
    //
    //  MARK: Private class functions
    //
    
    private class func obtainKey(tag: String, keySize: Int? = nil) -> SecKeyRef? {
        var keyRef: Unmanaged<AnyObject>?
        var query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnRef): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
        ]
        
        if let size = keySize {
            query[String(kSecAttrKeySizeInBits)] = size
        }
        
        let result: SecKeyRef?
        
        switch SecItemCopyMatching(query, &keyRef) {
        case noErr:
            result = Optional(keyRef?.takeRetainedValue() as! SecKeyRef)
        default:
            result = nil
        }
        
        return result
    }
    
    private class func obtainKeyData(tag: String, keySize: Int? = nil) -> NSData? {
        var keyRef: Unmanaged<AnyObject>?
        var query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
        ]
        
        if let size = keySize {
            query[String(kSecAttrKeySizeInBits)] = size
        }
        
        let result: NSData?
        
        switch SecItemCopyMatching(query, &keyRef) {
        case noErr:
            result = Optional(keyRef?.takeRetainedValue() as! NSData)
        default:
            result = nil
        }
        
        return result
    }
    
    private class func updateKey(tag: String, keySize: Int? = nil, data: NSData) -> Bool {
        var query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef]
        
        if let size = keySize {
            query[String(kSecAttrKeySizeInBits)] = size
        }
        
        return SecItemUpdate(query, [String(kSecValueData): data]) == noErr
    }
    
    private class func deleteKey(tag: String, keySize: Int? = nil) -> Bool {
        var query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef]
        
        if let size = keySize {
            query[String(kSecAttrKeySizeInBits)] = size
        }
        
        return SecItemDelete(query) == noErr
    }
    
    private class func insertPublicKey(publicTag: String, data: NSData) -> SecKeyRef? {
        var publicAttributes = Dictionary<String, AnyObject>()
        publicAttributes[String(kSecAttrKeyType)] = kSecAttrKeyTypeRSA
        publicAttributes[String(kSecClass)] = kSecClassKey as CFStringRef
        publicAttributes[String(kSecAttrApplicationTag)] = publicTag as CFStringRef
        publicAttributes[String(kSecValueData)] = data as CFDataRef
        publicAttributes[String(kSecAttrKeyClass)] = kSecAttrKeyClassPublic as CFStringRef
        publicAttributes[String(kSecReturnPersistentRef)] = true as CFBooleanRef
        
        var persistentRef = Unmanaged<AnyObject>?()
        let result: SecKeyRef?
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
                              kSecPublicKeyAttrs.takeUnretainedValue() as! String: publicAttributes,
                              kSecPrivateKeyAttrs.takeUnretainedValue() as! String: privateAttributes]
        
        var publicRef = Unmanaged<SecKey>?()
        var privateRef = Unmanaged<SecKey>?()
        switch SecKeyGeneratePair(pairAttributes, &publicRef, &privateRef) {
            case noErr:
                if let publicKey = publicRef, privateKey = privateRef {
                    return (publicKey.takeRetainedValue(), privateKey.takeRetainedValue())
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
    
    
    private class func encrypt(string: String, key: NSData) -> NSData? {
        if let stringData = (string as NSString).dataUsingEncoding(NSUTF8StringEncoding) {
            let data = UnsafePointer<UInt8>(stringData.bytes)
            let dataLength = stringData.length
            
            if let result = NSMutableData(length: dataLength + kCCBlockSizeAES128) {
                let keyData = UnsafePointer<UInt8>(key.bytes)
                let keyLength = size_t(key.length)
                
                var encryptedData = UnsafeMutablePointer<UInt8>(result.mutableBytes)
                let encryptedDataLength = size_t(result.length)
                
                var encryptedLength: size_t = 0
                
                let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionECBMode + kCCOptionPKCS7Padding), keyData, keyLength, nil, data, dataLength, encryptedData, encryptedDataLength, &encryptedLength)
                
                if UInt32(status) == UInt32(kCCSuccess) {
                    result.length = Int(encryptedLength)
                    return result
                }
            }
        }
        
        return nil
    }
    
    private class func decrypt(data: NSData, key: NSData) -> NSData? {
        let encryptedData = UnsafePointer<UInt8>(data.bytes)
        let encryptedDataLength = data.length
        
        if let result = NSMutableData(length: encryptedDataLength) {
            let keyData = UnsafePointer<UInt8>(key.bytes)
            let keyLength = size_t(key.length)
            
            var decryptedData = UnsafeMutablePointer<UInt8>(result.mutableBytes)
            let decryptedDataLength = size_t(result.length)
            
            var decryptedLength: size_t = 0
            
            let status = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionECBMode + kCCOptionPKCS7Padding), keyData, keyLength, nil, encryptedData, encryptedDataLength, decryptedData, decryptedDataLength, &decryptedLength)
            
            if UInt32(status) == UInt32(kCCSuccess) {
                result.length = Int(decryptedLength)
                return result
            }
        }

        return nil
    }
}


///
/// Manipulating data to include/exclude X509 headers
///
private extension NSData {
    func dataByPrependingX509Header() -> NSData {
        let result = NSMutableData()
        
        let encodingLength: Int = {
            if self.length + 1 < 128 {
                return 1
            } else {
                return ((self.length + 1) / 256) + 2
            }
            }()
        
        func encodeLength(length: Int) -> [CUnsignedChar] {
            if length < 128 {
                return [CUnsignedChar(length)];
            }
            
            var i = (length / 256) + 1
            var len = length
            var result: [CUnsignedChar] = [CUnsignedChar(i + 0x80)]
            
            for (var j = 0; j < i; j++) {
                result.insert(CUnsignedChar(len & 0xFF), atIndex: 1)
                len = len >> 8
            }
            
            return result
        }
        
        let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
        
        var builder: [CUnsignedChar] = []
        
        // ASN.1 SEQUENCE
        builder.append(0x30)
        
        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.length
        let encodedSize = encodeLength(size)
        builder.extend(encodedSize)
        result.appendBytes(builder, length: builder.count)
        result.appendBytes(OID, length: OID.count)
        builder.removeAll(keepCapacity: false)
        
        builder.append(0x03)
        builder.extend(encodeLength(self.length + 1))
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
        
        if bytes[offset++] == 0x30 {
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80 + 1
            } else {
                offset++
            }
            
            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let slice: [CUnsignedChar] = Array(bytes[offset...(offset + OID.count)])
            
            if slice == OID {
                offset += OID.count
                
                if bytes[offset++] != 0x03 {
                    return self
                }
                
                if bytes[offset] > 0x80 {
                    offset += Int(bytes[offset]) - 0x80 + 1
                } else {
                    offset++
                }
                
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

