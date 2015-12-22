Pod::Spec.new do |s|
  s.name                        = "VirgilFoundation"
  s.version                     = "1.3.0-alpha.vf.1"
  s.summary                     = "VirgilFoundation is an apple-cross-platform framework which contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signs."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-crypto-ios"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.author                      = { "Pavlo Gorb" => "p.orbitum@gmail.com" }
  s.platforms                   = { :osx => "10.10" :ios => "8.0", :watchos => "2.0", :tvos => "9.0" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-crypto-ios.git", :tag => "1.3.0-alpha.vf.1" }
  s.source_files                = "Wrapper/*"
  s.public_header_files         = "Wrapper/*.h"
  s.requires_arc                = true
  s.library                     = "stdc++"
  s.osx.vendored_frameworks     = "Frameworks/osx/*.framework"
  s.ios.vendored_frameworks     = "Frameworks/ios/*.framework"
  s.watchos.vendored_frameworks = "Frameworks/watchos/*.framework"
  s.tvos.vendored_frameworks    = "Frameworks/tvos/*.framework"
  s.xcconfig                    = { "HEADER_SEARCH_PATHS" => "$(FRAMEWORK_SEARCH_PATHS)/VirgilCrypto.framework/Headers" }
end

