Pod::Spec.new do |s|

  s.name        = "Heimdall"
  s.version     = "1.1.5"
  s.summary     = "Heimdall is a wrapper around the Security framework for simple encryption/decryption operations."
  s.license     = { :type => "MIT", :file => "LICENSE" }

  s.description = <<-DESC
                   Heimdall acts as a gatekeeper between UI and the underlying Security frameworks, offering
                   tools for encryption/decryption, as well as signing/verifying.

                   Heimdall supports both using a RSA public-private key-pair, as well as just a public key,
                   which allows for multiple parties to verify and encrypt messages for sending.
                   DESC

  s.homepage    = "https://github.com/henrinormak/Heimdall"

  s.author              = { "Henri Normak" => "henri.normak@gmail.com" }
  s.social_media_url    = "http://twitter.com/henrinormak"

  s.platform     = :ios, "8.0"

  s.source       = { :git => "https://github.com/henrinormak/Heimdall.git", :tag => s.version.to_s }

  s.preserve_paths  = "CommonCrypto/*"
  s.source_files    = "Heimdall/*"
  s.requires_arc    = true

  s.xcconfig        = { 'SWIFT_INCLUDE_PATHS[sdk=iphonesimulator*]' => '$(PODS_ROOT)/Heimdall/CommonCrypto/iphonesimulator/',
                        'SWIFT_INCLUDE_PATHS[sdk=iphoneos*]' => '$(PODS_ROOT)/Heimdall/CommonCrypto/iphoneos/',
                        'SWIFT_INCLUDE_PATHS[sdk=appletvos*]' => '$(PODS_ROOT)/Heimdall/CommonCrypto/appletvos/',
                        'SWIFT_INCLUDE_PATHS[sdk=appletvsimulator*]' => '$(PODS_ROOT)/Heimdall/CommonCrypto/appletvsimulator/' }

  s.prepare_command = <<-CMD
                        mkdir -p CommonCrypto/iphoneos
                        mkdir -p CommonCrypto/iphonesimulator
                        mkdir -p CommonCrypto/appletvos
                        mkdir -p CommonCrypto/appletvsimulator
                        cp CommonCrypto/iphoneos.modulemap CommonCrypto/iphoneos/module.modulemap
                        cp CommonCrypto/iphonesimulator.modulemap CommonCrypto/iphonesimulator/module.modulemap
                        cp CommonCrypto/iphonesimulator.modulemap CommonCrypto/appletvos/module.modulemap
                        cp CommonCrypto/iphonesimulator.modulemap CommonCrypto/appletvsimulator/module.modulemap
                        CMD

end
