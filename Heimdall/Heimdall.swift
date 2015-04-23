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
    let tag: String
    let privateTag: String
    let keySize: Int
    
    public enum KeyType {
        case Public
        case Private
    }
    
    public init?(tag: String, keySize: Int = 2048) {
        let privateTag = tag + ".private"
        
        self.tag = tag
        self.privateTag = privateTag
        self.keySize = keySize
        
        // If we already have both keys, then the permanent flag can be ignored
        // otherwise we need to generate (and potentially store) the keys
        if Heimdall.obtainKey(tag, keySize: keySize) == nil || Heimdall.obtainKey(privateTag, keySize: keySize) == nil {
            let result = Heimdall.generateKeyPair(tag, privateTag: privateTag, keySize: keySize)
            if result == nil {
                return nil
            }
        }
    }
    
    //
    //  Public functions
    //
    
    ///
    /// :returns: Public key in X.509 format as a base64 string (URL safe)
    ///
    public func X509PublicKey() -> NSString? {
        if let key = obtainKeyData(.Public) {
            let result = NSMutableData()
            
            let encodingLength: Int = {
                if key.length + 1 < 128 {
                    return 1
                } else {
                    return ((key.length + 1) / 256) + 2
                }
                }()
            
            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            
            var builder: [CUnsignedChar] = []
            
            // ASN.1 SEQUENCE
            builder.append(0x30)
            
            // Overall size, made of OID + bitstring encoding + actual key
            let size = OID.count + 2 + encodingLength + key.length
            let encodedSize = Heimdall.encodeLength(size)
            builder.extend(encodedSize)
            result.appendBytes(builder, length: builder.count)
            result.appendBytes(OID, length: OID.count)
            builder.removeAll(keepCapacity: false)
            
            builder.append(0x03)
            builder.extend(Heimdall.encodeLength(key.length + 1))
            builder.append(0x00)
            result.appendBytes(builder, length: builder.count)
            
            // Actual key bytes
            result.appendData(key)
            
            // Convert to Base64 and make safe for URLs
            var string = result.base64EncodedStringWithOptions(.allZeros)
            string = string.stringByReplacingOccurrencesOfString("/", withString: "_")
            string = string.stringByReplacingOccurrencesOfString("+", withString: "-")
            
            return string
        }
        
        return nil
    }
    
    ///
    /// Encrypt an arbitrary string using the public key of the pair
    ///
    /// :param: string      Input string to be encrypted
    /// :param: urlEncode   If true, resulting Base64 string is URL encoded
    ///
    /// :returns: The encrypted version of the string, as Base64 string
    ///
    public func encrypt(string: String, urlEncode: Bool = false) -> String? {
        if let key = obtainKey(.Public), data = Heimdall.encrypt(string, secKey: key, blockSize: SecKeyGetBlockSize(key)) {
            var result = data.base64EncodedStringWithOptions(.allZeros)
            
            if urlEncode {
                result = result.stringByReplacingOccurrencesOfString("/", withString: "_")
                result = result.stringByReplacingOccurrencesOfString("+", withString: "-")
            }
            
            return result
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
        if urlEncoded {
            base64String = base64String.stringByReplacingOccurrencesOfString("_", withString: "/")
            base64String = base64String.stringByReplacingOccurrencesOfString("-", withString: "+")
        }
        
        if let encryptedData = NSData(base64EncodedString: base64String, options: .allZeros) {
            if let key = obtainKey(.Private), data = Heimdall.decrypt(encryptedData, secKey: key, blockSize: SecKeyGetBlockSize(key)) {
                return NSString(data:data, encoding:NSUTF8StringEncoding) as? String
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
        // Convert the message to data
        if let messageData = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
            // Create SHA256 hash of the message
            if let hash = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) {
                CC_SHA256(messageData.bytes, CC_LONG(messageData.length), UnsafeMutablePointer(hash.mutableBytes))
                
                // Sign the hash with the private key
                if let key = obtainKey(.Private) {
                    let blockSize = SecKeyGetBlockSize(key)
                    
                    let hashDataLength = Int(hash.length)
                    var hashData = [UInt8](count: hashDataLength, repeatedValue: 0)
                    hash.getBytes(&hashData, length:hashDataLength)
                    
                    var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
                    var encryptedDataLength = blockSize
                    
                    let result = SecKeyRawSign(key, SecPadding(kSecPaddingPKCS1SHA256), hashData, hashDataLength, &encryptedData, &encryptedDataLength)
                    
                    // Base64 of the result
                    let signatureData = NSData(bytes: &encryptedData, length: Int(encryptedDataLength))
                    var signature = signatureData.base64EncodedStringWithOptions(.allZeros)
                    
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
    /// :returns: true if the signature is valid
    ///
    public func verify(message: String, var signatureBase64: String, urlEncoded: Bool = true) -> Bool {
        if urlEncoded {
            signatureBase64 = signatureBase64.stringByReplacingOccurrencesOfString("_", withString: "/")
            signatureBase64 = signatureBase64.stringByReplacingOccurrencesOfString("-", withString: "+")
        }
        
        if let signature = NSData(base64EncodedString: signatureBase64, options: .allZeros),
                messageData = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false),
                hashData = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) {
            
            CC_SHA256(messageData.bytes, CC_LONG(messageData.length), UnsafeMutablePointer(hashData.mutableBytes))
            var signedData = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
            hashData.getBytes(&signedData, length:Int(CC_SHA256_DIGEST_LENGTH))
            
            let signatureLength = Int(signature.length)
            var signatureData = [UInt8](count: signatureLength, repeatedValue: 0)
            signature.getBytes(&signatureData, length: signatureLength)
            
            if let key = obtainKey(.Public) {
                let result = SecKeyRawVerify(key, SecPadding(kSecPaddingPKCS1SHA256), &signedData, Int(CC_SHA256_DIGEST_LENGTH), &signatureData, signatureLength)
                
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
        var items = [[String: AnyObject]]()
        
        // Private key
        var query = [String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): self.privateTag as CFStringRef]
        
        let privateResult = SecItemDelete(query)
        
        // Public key
        query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): self.tag as CFStringRef]
        
        let publicResult = SecItemDelete(query)
        
        if privateResult == noErr && publicResult == noErr {
            return true
        } else {
            println("Error deleting items \(privateResult), \(publicResult)")
        }
        
        return false
    }
    
    //
    //  Private helpers
    //
    private func obtainKey(key: KeyType) -> SecKeyRef? {
        let tag: String = {
            switch key {
            case .Public:
                return self.tag
            case .Private:
                return self.privateTag
            }
            }()
        
        return Heimdall.obtainKey(tag, keySize: self.keySize)
    }
    
    private func obtainKeyData(key: KeyType) -> NSData? {
        let tag: String = {
            switch key {
            case .Public:
                return self.tag
            case .Private:
                return self.privateTag
            }
        }()
        
        return Heimdall.obtainKeyData(tag, keySize: self.keySize)
    }
    
    //
    //  Private class functions
    //
    
    private class func obtainKey(tag: String, keySize: Int) -> SecKeyRef? {
        var keyRef: Unmanaged<AnyObject>?
        let query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): keySize,
            String(kSecReturnRef): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
        ]
        
        let result: SecKeyRef?
        
        switch SecItemCopyMatching(query, &keyRef) {
        case noErr:
            result = Optional(keyRef?.takeRetainedValue() as! SecKeyRef)
        default:
            result = nil
        }
        
        return result
    }
    
    private class func obtainKeyData(tag: String, keySize: Int) -> NSData? {
        var keyRef: Unmanaged<AnyObject>?
        var query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): keySize,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
        ]
        
        let result: NSData?
        
        switch SecItemCopyMatching(query, &keyRef) {
        case noErr:
            result = Optional(keyRef?.takeRetainedValue() as! NSData)
        default:
            result = nil
        }
        
        return result
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
    
    private class func encodeLength(length: Int) -> [CUnsignedChar] {
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
    
    private class func encrypt(string: String, secKey: SecKeyRef, blockSize: Int) -> NSData? {
        if string.startIndex == string.endIndex {
            return nil
        }
                
        let length = count(string)
        let blockLength = blockSize - 11
        var range = Range<String.Index>(start: string.startIndex, end: advance(string.startIndex, blockLength, string.endIndex))
        
        var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var encryptedLength = blockSize
        
        let result = NSMutableData()
        
        // First range is always there
        let substring = string.substringWithRange(range)
        var data = [UInt8](substring.utf8)
        
        switch SecKeyEncrypt(secKey, SecPadding(kSecPaddingPKCS1), &data, distance(range.startIndex, range.endIndex), &encryptedData, &encryptedLength) {
            case noErr:
                result.appendBytes(&encryptedData, length: encryptedLength)
            default:
                return nil
        }
        
        // Remaining ranges are only accessible if we have not yet reached the end of the string
        while range.endIndex != string.endIndex {
            range = Range<String.Index>(start: range.endIndex, end: advance(range.endIndex, blockLength, string.endIndex))

            let substring = string.substringWithRange(range)
            var data = [UInt8](substring.utf8)
            
            switch SecKeyEncrypt(secKey, SecPadding(kSecPaddingPKCS1), &data, distance(range.startIndex, range.endIndex), &encryptedData, &encryptedLength) {
                case noErr:
                    result.appendBytes(&encryptedData, length: encryptedLength)
                default:
                    return nil
            }
        }
        
        return result
    }
    
    private class func decrypt(data: NSData, secKey: SecKeyRef, blockSize: Int) -> NSData? {
        if data.length < blockSize {
            return nil
        }
        
        let result = NSMutableData()
        
        let encryptedDataLength: Int = blockSize
        var range = NSRange(location: 0, length: blockSize)
        var encryptedData = [UInt8](count: encryptedDataLength, repeatedValue: 0)

        var decryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var decryptedDataLength = blockSize
        
        while NSMaxRange(range) <= data.length {
            data.getBytes(&encryptedData, range: range)
            
            switch SecKeyDecrypt(secKey, SecPadding(kSecPaddingPKCS1), encryptedData, range.length, &decryptedData, &decryptedDataLength) {
                case noErr:
                    result.appendBytes(&decryptedData, length: decryptedDataLength)
                default:
                    return nil
            }
            
            let end = range.location + range.length
            range = NSRange(location: end, length: blockSize)
        }
        
        return result
    }
}
