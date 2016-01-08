Pod::Spec.new do |s|
  s.name                    = "VirgilCryptoiOS"
  s.version                 = "1.3.1"
  s.summary                 = "VirgilCryptoiOS contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signs."
  s.homepage                = "https://github.com/VirgilSecurity/VirgilCryptoiOS"
  s.license                 = { :type => "BSD", :file => "LICENSE" }
  s.author                  = { "Pavlo Gorb" => "p.orbitum@gmail.com" }
  s.platforms               = { :ios => "8.0" }
  s.source                  = { :git => "https://github.com/VirgilSecurity/VirgilCryptoiOS.git", :tag => "1.3.1" }
  s.source_files            = "Wrapper/*"
  s.public_header_files     = "Wrapper/*.h"
  s.requires_arc            = true
  s.library                 = "stdc++"
  s.vendored_frameworks     = "Frameworks/ios/*.framework"
  s.xcconfig                = { "HEADER_SEARCH_PATHS" => "$(FRAMEWORK_SEARCH_PATHS)/VirgilCrypto.framework/Headers" }
  s.deprecated              = true
  s.deprecated_in_favor_of  = 'VirgilFoundation'
end
