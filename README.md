# Heimdall

In Norse mythology, Heimdall is the gatekeeper of Bifröst, the rainbow road connecting Midgard, realm of the humans, to Asgard, the realm of gods.

In iOS, Heimdall serves as a gatekeeper between Security framework and the UI, offering a nice wrapper around the C APIs for encrypting, decrypting, signing and verifying messages.

Furthermore, Heimdall also helps maintain the public-private RSA key-pair in Keychain, allowing both creating as well as deleting the key pairs.

## Installation

### Subproject

As Heimdall makes use of CommonCrypto and has it wrapped in a pseudo-module, the easiest way to use Heimdall is to include the entire project (or the produced framework).

Easiest way to use Heimdall is to include the `Heimdall.xcodeproj` into your Xcode project. Then specify the `Heimdall` target as **Target Dependency**.

![Target Dependency selection in Xcode](/Images/target_dependency.png?raw=true "Target Dependency")

Finally, make sure Heimdall is listed under the **Embedded Binaries** section in Xcode

![Embedded Binaries under application target settings](/Images/embedded_binary.png?raw=true "Embedded Binary")

### Directly

If you have a bridging header in place, you can also simply include `Heimdall.swift` to your project and add `#import <CommonCrypto/CommonDigest.h>` to your bridging header.

## Contributing

Currently, Heimdall offers minimal functionality, pull requests and issues are all welcome, especially for the following topics:

* Security, interacting with the Keychain, making sure the results are kept securely etc.
* Tests, adding tests would also likely increase security
* Additional configurability, perhaps allowing non-permanent keys
* Error handling, currently most of the API simply returns `nil`s whenever an error occurs, this should be changed and proper error reporting should be implemented
* CocoaPods/Carthage support, perhaps some users prefer using dependencies over CocoaPods/Carthage

## Contact

If you have any questions, don't hesitate to contact me.
In case of bugs, create an issue here on GitHub

Henri Normak

- http://github.com/henrinormak
- http://twitter.com/henrinormak

## License

```
The MIT License (MIT)

Copyright (c) 2014 Henri Normak

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
