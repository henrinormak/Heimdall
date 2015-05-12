![Heimdall Helmet](/Images/heimdall_icon.png "Heimdall Helmet")

# Heimdall

In Norse mythology, Heimdall is the gatekeeper of Bifröst, the rainbow road connecting Midgard, realm of the humans, to Asgard, the realm of gods.

In iOS, Heimdall serves as a gatekeeper between Security framework and the UI, offering a nice wrapper around the C APIs for encrypting, decrypting, signing and verifying messages.

Furthermore, Heimdall also helps maintain the public-private RSA key-pair in Keychain, allowing both creating as well as deleting the key pairs.

## Requirements

Heimdall requires Swift 1.2, and is only compatible with iOS 8 and above.

## Installation

### CocoaPods

Heimdall is available as a CocoaPod, simply add the following line to your Podfile

```ruby
pod 'Heimdall', '~> 0.1'
```

Also, make sure your podfile includes the following line, which is necessary to support Swift frameworks

```ruby
use_frameworks!
```

### Carthage (unconfirmed)

As the `Heimdall.xcodeproj` produces a dynamic framework, Heimdall should function properly with Carthage. This has not been confirmed.

### Subproject

As Heimdall makes use of `CommonCrypto` and has it wrapped in a pseudo-module, the easiest way to use Heimdall is to include the entire project as a subproject in your workspace.

To do this, include `Heimdall.xcodeproj` (found in Heimdall folder) into your Xcode workspace. Then specify the `Heimdall` target as a **Target Dependency** for your main application target.

![Target Dependency selection in Xcode](/Images/target_dependency.png?raw=true "Target Dependency")

Finally, make sure Heimdall is listed under the **Embedded Binaries** section in Xcode

![Embedded Binaries under application target settings](/Images/embedded_binary.png?raw=true "Embedded Binary")

### Directly

Although not recommended, you can also add Heimdall directly, by including `Heimdall.swift` in your project.

As Heimdall uses `CommonCrypto`, you also need to include a build phase for the following script, which needs to occur before compilation of `Heimdall.swift`

```bash
modulesDirectory=$DERIVED_FILES_DIR/modules
modulesMap=$modulesDirectory/module.modulemap
modulesMapTemp=$modulesDirectory/module.modulemap.tmp

mkdir -p "$modulesDirectory"

cat > "$modulesMapTemp" << MAP
module CommonCrypto [system] {
    header "$SDKROOT/usr/include/CommonCrypto/CommonCrypto.h"
    export *
}
MAP

diff "$modulesMapTemp" "$modulesMap" >/dev/null 2>/dev/null
if [[ $? != 0 ]] ; then
    mv "$modulesMapTemp" "$modulesMap"
else
    rm "$modulesMapTemp"
fi
```

In addition, the add the following path (`$(DERIVED_DATA_DIR)/modules`) to the **Include Paths** (SWIFT_INCLUDE_PATHS) build setting


## Usage

Using Heimdall is simple, for public-private key-pair, you just have to create an instance, which can be used for encryption/decryption, signing/verifying.

With this method you can locally encrypt data to be stored on disk or in a database, without putting everything in the Keychain.

```swift
if let heimdall = Heimdall(tagPrefix: "com.example") {
    let testString = "This is a test string"

    // Encryption/Decryption
    if let encryptedString = heimdall.encrypt(testString) {
        println(encryptedString) // "cQzaQCQLhAWqkDyPoHnPrpsVh..."

        if let decryptedString = heimdall.decrypt(encryptedString) {
            println(decryptedString) // "This is a test string"
        }
    }

    // Signatures/Verification
    if let signature = heimdall.sign(testString) {
        println(signature) // "fMVOFj6SQ7h+cZTEXZxkpgaDsMrki..."
        var verified = heimdall.verify(testString, signatureBase64: signature)
        println(verified) // True

        // If someone meddles with the message and the signature becomes invalid
        verified = heimdall.verify(testString + "injected false message",
                                    signatureBase64: signature)
        println(verified) // False
    }
}
```

### Complex use case

A more complex use case involves exchanging encrypted messages between multiple Heimdall instances, which can be situated on multiple different hosts.

The workflow should be mirrored on all hosts, extracting their public keys and sharing those to all other parties. The public keys can be used to construct special Heimdall instances that are only able to encrypt messages and verify signatures.

```swift
let localHeimdall = Heimdall(tagPrefix: "com.example")

if let heimdall = localHeimdall {
    let publicKeyData = heimdall.X509PublicKey()
    var publicKeyString = publicKeyData.base64EncodedStringWithOptions(.allZeros)

    // If you want to make this string URL safe,
    // you have to remember to do the reverse on the other side later
    publicKeyString = publicKeyString.stringByReplacingOccurrencesOfString("/", withString: "_")
    publicKeyString = publicKeyString.stringByReplacingOccurrencesOfString("+", withString: "-")

    println(publicKeyString) // Something along the lines of "MIGfMA0GCSqGSIb3DQEBAQUAA..."

    // Data transmission of public key to the other party
}

// On other party, assuming keyData contains the received public key data
if let partnerHeimdall = Heimdall(publicTag: "com.example.partner", publicKeyData: keyData) {
    // Transmit some message to the partner
    let message = "This is a secret message to my partner"
    let encryptedMessage = partnerHeimdall.encrypt(message)

    // Transmit the encryptedMessage
}

// Initial host receives encryptedMessage
if let heimdall = localHeimdall {
    if let decryptedMessage = heimdall.decrypt(encryptedMessage) {
        println(decryptedMessage) // "This is a secret message to my partner"
    }
}

```

## Contributing and Current Work

Currently, Heimdall offers minimal functionality, pull requests and issues are all welcome, especially for the following topics:

* Security, interacting with the Keychain, making sure the results are kept securely etc.
* Tests, adding tests would also likely increase security
* Additional configurability, perhaps allowing non-permanent keys
* Error handling, currently most of the API simply returns `nil`s whenever an error occurs, this should be changed and proper error reporting should be implemented
* Reducing the number of optionals in the public API of the Heimdall instances.

## Contact

If you have any questions, don't hesitate to contact me.
In case of bugs, create an issue here on GitHub

Henri Normak

- http://github.com/henrinormak
- http://twitter.com/henrinormak

## License

```
The MIT License (MIT)

Copyright (c) 2015 Henri Normak

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
