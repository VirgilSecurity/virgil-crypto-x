Pod::Spec.new do |s|
  s.name                  = "VirgilCryptoiOS"
  s.version               = "1.1.0"
  s.summary               = "VirgilCryptoiOS contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signs."
  s.homepage              = "https://github.com/VirgilSecurity/VirgilCryptoiOS"
  s.license               = { :type => "BSD", :file => "LICENSE" }
  s.author                = { "Pavlo Gorb" => "p.orbitum@gmail.com" }
  s.platform              = :ios, "8.0"
  s.source                = { :git => "https://github.com/VirgilSecurity/VirgilCryptoiOS.git", :tag => "1.1.0" }
  s.source_files          = "Wrapper/*"
  s.public_header_files   = "Wrapper/*.h"
  s.requires_arc          = true
  s.library               = "stdc++"
  s.vendored_frameworks   = "Frameworks/*.framework"
  s.xcconfig              = { "HEADER_SEARCH_PATHS" => "$(PODS_VIRGILCRYPTOIOS_FRAMEWORK_SEARCH_PATHS)/VirgilSecurity.framework/Headers" }
end
