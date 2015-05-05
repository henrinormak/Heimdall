Pod::Spec.new do |s|

  s.name        = "Heimdall"
  s.version     = "0.1"
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

  s.preserve_paths  = "Heimdall/CommonCrypto/*"
  s.source_files    = "Heimdall/Heimdall/*"
  s.requires_arc    = true

  s.xcconfig        = { 'SWIFT_INCLUDE_PATHS[sdk=iphonesimulator*]' => '$(PODS_ROOT)/Heimdall/Heimdall/CommonCrypto/iphonesimulator/',
                        'SWIFT_INCLUDE_PATHS[sdk=iphoneos*]' => '$(PODS_ROOT)/Heimdall/Heimdall/CommonCrypto/iphoneos/' }

  s.prepare_command = <<-CMD
                        mkdir -p Heimdall/CommonCrypto/iphoneos
                        mkdir -p Heimdall/CommonCrypto/iphonesimulator
                        cp Heimdall/CommonCrypto/iphoneos.modulemap Heimdall/CommonCrypto/iphoneos/module.modulemap
                        cp Heimdall/CommonCrypto/iphonesimulator.modulemap Heimdall/CommonCrypto/iphonesimulator/module.modulemap
                        CMD

end
