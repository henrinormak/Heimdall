Pod::Spec.new do |s|

  s.name        = "Heimdall"
  s.version     = "2.0.0"
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

  s.source_files    = "Heimdall/*"
  s.requires_arc    = true

end
