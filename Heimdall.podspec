Pod::Spec.new do |s|

  s.name        = "Heimdall"
  s.version     = "1.1.2"
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


  #
  # Create the dummy CommonCrypto.framework structures
  #
  s.prepare_command = <<-CMD
    touch prepare_command.txt
    echo 'Running prepare_command'
    pwd
    echo Running GenerateCommonCryptoModule
    swift ./GenerateCommonCryptoModule.swift macosx .
    swift ./GenerateCommonCryptoModule.swift iphonesimulator .
    swift ./GenerateCommonCryptoModule.swift iphoneos .
    swift ./GenerateCommonCryptoModule.swift appletvsimulator .
    swift ./GenerateCommonCryptoModule.swift appletvos .
    swift ./GenerateCommonCryptoModule.swift watchsimulator .
    swift ./GenerateCommonCryptoModule.swift watchos .

  CMD

  # Stop CocoaPods from deleting dummy frameworks
  s.preserve_paths  = "Frameworks"

  s.source_files    = "Heimdall/*"
  s.requires_arc    = true


  # Make sure we can find the dummy frameworks
  s.xcconfig = { 
    "SWIFT_VERSION" => "3.0",
    "SWIFT_INCLUDE_PATHS" => "${PODS_ROOT}/Heimdall/Frameworks/$(PLATFORM_NAME)",
    "FRAMEWORK_SEARCH_PATHS" => "${PODS_ROOT}/Heimdall/Frameworks/$(PLATFORM_NAME)"
  }

end
