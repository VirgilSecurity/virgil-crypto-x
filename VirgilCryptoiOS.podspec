Pod::Spec.new do |s|
  s.name         = "VirgilCryptoiOS"
  s.version      = "1.0.0"
  s.summary      = "VirgilCryptoiOS contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signs."
  s.homepage     = "https://github.com/VirgilSecurity/virgil-iOS/tree/master/VirgilCryptoiOS"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Pavlo Gorb" => "p.orbitum@gmail.com" }
  s.platform     = :ios, "8.0"
  s.source       = { :git => "https://github.com/VirgilSecurity/virgil-iOS/tree/master/VirgilCryptoiOS", :tag => "1.0.0" }
  s.source_files  = "Wrapper", "Wrapper/**/*"
  s.public_header_files = "Wrapper/**/*.h"
  s.framework  = "Foundation"
  s.requires_arc = true
  s.vendored_frameworks = "Frameworks/*",
  s.xcconfig = { "HEADER_SEARCH_PATHS" => "Frameworks/VirgilSecurity.framework/Headers" }
end
