//
//  HeimdallTests.swift
//  HeimdallTests
//
//  Created by Henri Normak on 23/04/15.
//  Copyright (c) 2015 Henri Normak. All rights reserved.
//

import XCTest
import Heimdall

class HeimdallTests: XCTestCase {
    var publicHeimdall: Heimdall!
    var privateHeimdall: Heimdall!
    
    var destroyedPublicHeimdall: Heimdall!
    var destroyedPrivateHeimdall: Heimdall!
    
    override func setUp() {
        self.privateHeimdall = Heimdall(tagPrefix: "com.hnormak.heimdall.private.tests", keySize: 2048)!
        self.privateHeimdall.regenerate(2048) // Make sure that nothing leaks between tests

        self.publicHeimdall = Heimdall(publicTag: "com.hnormak.heimdall.tests", publicKeyData: self.privateHeimdall.publicKeyData()!)!
        
        self.destroyedPrivateHeimdall = Heimdall(tagPrefix: "com.hnormak.heimdall.private.destroyed.tests", keySize: 2048)!
        self.destroyedPrivateHeimdall.destroy()
        
        self.destroyedPublicHeimdall = Heimdall(publicTag: "com.hnormak.heimdall.destroyed.tests", publicKeyData: self.privateHeimdall.publicKeyData()!)!
        self.destroyedPublicHeimdall.destroy()
    }
    
    override func tearDown() {
        self.publicHeimdall.destroy()
        self.privateHeimdall.destroy()
    }
    
    func testInitialisation() {
        // We have four initialisers, test them all with valid, as well as invalid data
        // Basic initialiser
        let basic = Heimdall(tagPrefix: "private.initialisation", keySize: 2048)
        XCTAssertNotNil(basic)
        basic?.destroy()
        
        // Different tags for public/private key pairs, make sure that one is not a prefix of the other
        let customisedTags = Heimdall(publicTag: "custom.tag.initialisation", privateTag: "custom.private.tag.initialisation", keySize: 2048)
        XCTAssertNotNil(customisedTags)
        customisedTags?.destroy()
        
        // Public key data based initialisation
        let publicKeyData = Data(base64Encoded: "MIIBCgKCAQEA2Ddg4jCLE7VPxLPjBaTPH3DSXpkJQP3J5KycZBUF4dyWJTeY8m5HyTrRj+Dm5t3ccpPJSd+OjupHdUj+BtL+8g+NOddmUCr0gmQsxsXx8ex+lS+wHgRBmH/Cb/5lZ1Ml7Omtysz8G/pw6LGYK9C0s0ZoUOAApv/rC9vQ1T8S0eJPJIB8rHsfnvrxkC9Cwkftu5pOIv5fqrjsDLqn0dLypWyT8AhHSdgRZn0658efTyPytfnu2/1XiOzzCbNxPExv+n8fq1kkzSIg9+gN7tvPz+gpbv1eQsDkArrGx838EqW8o5cUbGA3DtlGWAr4dKTe3yY40CA55AMz/lvmU0dnRwIDAQAB", options: [])!
        let pubData = Heimdall(publicTag: "public.initialisation", publicKeyData: publicKeyData)
        XCTAssertNotNil(pubData)
        pubData?.destroy()
        
        // Public key components based initialisation
        let pubKeyModulus = Data(base64Encoded: "ANg3YOIwixO1T8Sz4wWkzx9w0l6ZCUD9yeSsnGQVBeHcliU3mPJuR8k60Y/g5ubd3HKTyUnfjo7qR3VI/gbS/vIPjTnXZlAq9IJkLMbF8fHsfpUvsB4EQZh/wm/+ZWdTJezprcrM/Bv6cOixmCvQtLNGaFDgAKb/6wvb0NU/EtHiTySAfKx7H5768ZAvQsJH7buaTiL+X6q47Ay6p9HS8qVsk/AIR0nYEWZ9OufHn08j8rX57tv9V4js8wmzcTxMb/p/H6tZJM0iIPfoDe7bz8/oKW79XkLA5AK6xsfN/BKlvKOXFGxgNw7ZRlgK+HSk3t8mONAgOeQDM/5b5lNHZ0c=", options: [])!
        let pubKeyExponent = Data(base64Encoded: "AQAB", options: [])!
        
        let pubComponents = Heimdall(publicTag: "public.components.initialisation", publicKeyModulus: pubKeyModulus, publicKeyExponent: pubKeyExponent)
        XCTAssertNotNil(pubComponents)
        pubComponents?.destroy()
        
        // Non-null starting modulus
        let alternativePubKeyModulus = Data(base64Encoded: "3JvrTKthRgmLnmugBwN3z3MCh9WiDIv+GX0rm181taXimmz/ZKP8kfuaZL4eLnqCejCM8CEKhX+2tJRpIrht360Sx7gBii5TUibumfMxTEZb/+1aGZCA/a/JjZUOrvGABDYqqn5FdZ7RFgrUtQsnpM7is0UXtV86omPw9Fh8HwU=", options: [])!
        let pubAlternativeComponents = Heimdall(publicTag: "public.components.alternative.initialisation", publicKeyModulus: alternativePubKeyModulus, publicKeyExponent: pubKeyExponent)
        XCTAssertNotNil(pubAlternativeComponents)
        pubAlternativeComponents?.destroy()
        
        // Public X.509 data based initialisation
        let publicKeyX509 = Data(base64Encoded: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Ddg4jCLE7VPxLPjBaTPH3DSXpkJQP3J5KycZBUF4dyWJTeY8m5HyTrRj+Dm5t3ccpPJSd+OjupHdUj+BtL+8g+NOddmUCr0gmQsxsXx8ex+lS+wHgRBmH/Cb/5lZ1Ml7Omtysz8G/pw6LGYK9C0s0ZoUOAApv/rC9vQ1T8S0eJPJIB8rHsfnvrxkC9Cwkftu5pOIv5fqrjsDLqn0dLypWyT8AhHSdgRZn0658efTyPytfnu2/1XiOzzCbNxPExv+n8fq1kkzSIg9+gN7tvPz+gpbv1eQsDkArrGx838EqW8o5cUbGA3DtlGWAr4dKTe3yY40CA55AMz/lvmU0dnRwIDAQAB", options: [])!
        
        let pubX509 = Heimdall(publicTag: "public.x509.initialisation", publicKeyData: publicKeyX509)
        XCTAssertNotNil(pubX509)
        pubX509?.destroy()
    }
    
    func testExport() {
        // Exporting the public key should work from both public/private instances, but not from destroyed instances
        XCTAssertNotNil(self.publicHeimdall.publicKeyData())
        XCTAssertNotNil(self.privateHeimdall.publicKeyData())
        XCTAssertNotNil(self.publicHeimdall.publicKeyDataX509())
        XCTAssertNotNil(self.privateHeimdall.publicKeyDataX509())
        XCTAssertTrue(self.publicHeimdall.publicKeyComponents() != nil)
        XCTAssertTrue(self.privateHeimdall.publicKeyComponents() != nil)
        
        XCTAssertNil(self.destroyedPublicHeimdall.publicKeyData())
        XCTAssertNil(self.destroyedPrivateHeimdall.publicKeyData())
        XCTAssertNil(self.destroyedPublicHeimdall.publicKeyDataX509())
        XCTAssertNil(self.destroyedPrivateHeimdall.publicKeyDataX509())
        XCTAssertFalse(self.destroyedPublicHeimdall.publicKeyComponents() != nil)
        XCTAssertFalse(self.destroyedPrivateHeimdall.publicKeyComponents() != nil)
    }
    
    func testSigning() {
        let testData = "This is a test string".data(using: String.Encoding.utf8)!
        
        // Test signing with an instance that should have the means to do so (private key based instance)
        XCTAssertNotNil(self.privateHeimdall.sign(testData))
        
        // Signing should fail for an instance which is created based on a public key
        XCTAssertNil(self.publicHeimdall.sign(testData))
        
        // Signing should also fail for any destroyed kind of heimdall
        XCTAssertNil(self.destroyedPublicHeimdall.sign(testData))
        XCTAssertNil(self.destroyedPrivateHeimdall.sign(testData))
        
        // We can also test that signature is always the same (it is solely dependent on the input string)
        let first = self.privateHeimdall.sign(testData)!
        let second = self.privateHeimdall.sign(testData)!
        XCTAssertEqual(first, second)
    }
    
    func testVerifying() {
        // Verification should work with both private and public heimdalls
        let testData = "This is a test string".data(using: String.Encoding.utf8)!
        let corruptedData = "This is a test injected string".data(using: String.Encoding.utf8)!
        let testSignature = self.privateHeimdall.sign(testData)!
        
        // Valid signature test
        XCTAssertTrue(self.privateHeimdall.verify(testData, signatureData: testSignature))
        XCTAssertTrue(self.publicHeimdall.verify(testData, signatureData: testSignature))
        
        // Invalid signature test
        XCTAssertFalse(self.privateHeimdall.verify(corruptedData, signatureData: testSignature))
        XCTAssertFalse(self.publicHeimdall.verify(corruptedData, signatureData: testSignature))
        
        // Destroyed Heimdalls should always fail
        XCTAssertFalse(self.destroyedPrivateHeimdall.verify(testData, signatureData: testSignature))
        XCTAssertFalse(self.destroyedPublicHeimdall.verify(testData, signatureData: testSignature))
        XCTAssertFalse(self.destroyedPrivateHeimdall.verify(corruptedData, signatureData: testSignature))
        XCTAssertFalse(self.destroyedPublicHeimdall.verify(corruptedData, signatureData: testSignature))
    }
    
    func testEncrypting() {
        // Encryption should work with both private and public Heimdalls
        let testData = "This is a test string".data(using: String.Encoding.utf8)!
        
        XCTAssertNotNil(self.privateHeimdall.encrypt(testData))
        XCTAssertNotNil(self.publicHeimdall.encrypt(testData))
        
        // It should however, fail with destroyed instances
        XCTAssertNil(self.destroyedPublicHeimdall.encrypt(testData))
        XCTAssertNil(self.destroyedPrivateHeimdall.encrypt(testData))
        
        // Due to the way Heimdall works, every time the encryption is invoked, the result
        // should be different, even if the input string remains the same
        let first = self.privateHeimdall.encrypt(testData)!
        let second = self.privateHeimdall.encrypt(testData)!
        XCTAssertNotEqual(first, second)
    }
    
    func testDecrypting() {
        // Decrypting should only work with a private Heimdall
        let testData = "This is a test string".data(using: String.Encoding.utf8)!
        
        // Encrypted by the same instance
        var encrypted = self.privateHeimdall.encrypt(testData)
        XCTAssertNotNil(encrypted)
        var decrypted = self.privateHeimdall.decrypt(encrypted!)
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(testData, decrypted!)
        
        // Encrypted by its public key counterpart
        encrypted = self.publicHeimdall.encrypt(testData)
        XCTAssertNotNil(encrypted)
        decrypted = self.privateHeimdall.decrypt(encrypted!)
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(testData, decrypted!)
    }
    
    // Generate a set of random strings, with exponential increase in length
    // starting from 1 to 2^length
    func generatePerformanceTestData(_ length: Int = 10) -> [String] {
        func randomAlphaNumericString(_ length: Int) -> String {
            
            let allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            let allowedCharsCount = UInt32(allowedChars.count)
            var randomString = ""
            
            for _ in (0..<length) {
                let randomNum = Int(arc4random_uniform(allowedCharsCount))
                let newCharacter = allowedChars[allowedChars.index(allowedChars.startIndex, offsetBy: randomNum)]
                randomString += String(newCharacter)
            }
            
            return randomString
        }
        
        // Generate a set of ten values that are encrypted and then
        // stored as a tuple (decrypted, encrypted)
        let strings = (0..<length).map { i in
            return randomAlphaNumericString(Int(pow(2.0, Double(i))))
        }
        
        return strings
    }
    
    // Measure the performance of encrypting/decrypting 15 strings
    // and then make sure the results are expected
    func testEncryptionDecryptionPerformance() {
        let testData = self.generatePerformanceTestData(15)
        var results = [(raw: String, encrypted: String?, decrypted: String?)]()
        
        // Measure performance of encrypting & decrypting the strings
        self.measure { 
            testData.forEach({ (string) in
                if let encrypted = self.privateHeimdall.encrypt(string) {
                    if let decrypted = self.privateHeimdall.decrypt(encrypted) {
                        results.append((string, encrypted, decrypted))
                    } else {
                        XCTFail("Failed to decrypt message \(encrypted)")
                    }
                } else {
                    XCTFail("Failed to encrypt message \(string)")
                }
            })
        }
        
        // Validate the results
        results.forEach { (tuple) in
            XCTAssertEqual(tuple.raw, tuple.decrypted, "Failed to encrypt/decrypt message \(tuple.raw) -> \(tuple.encrypted ?? "nil") -> \(tuple.decrypted ?? "nil")")
        }
    }
}
