Pod::Spec.new do |s|
  s.name                        = "VirgilCrypto"
  s.version                     = "3.0.0-beta7"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signatures."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.ios.deployment_target       = "8.0"
  s.osx.deployment_target       = "10.10"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source_files                = "VirgilCrypto/**/*.{h,mm}"
  s.public_header_files         = "VirgilCrypto/Source/*.h", "VirgilCrypto/Source/pfs/*.h"
  s.library                     = 'stdc++'
  s.ios.vendored_frameworks     = "VSCCrypto/PrebuiltFramework/iOS/VSCCrypto.framework"
  s.osx.vendored_frameworks     = "VSCCrypto/PrebuiltFramework/macOS/VSCCrypto.framework"
  s.tvos.vendored_frameworks    = "VSCCrypto/PrebuiltFramework/tvOS/VSCCrypto.framework"
  s.watchos.vendored_frameworks = "VSCCrypto/PrebuiltFramework/watchOS/VSCCrypto.framework"
end
