Pod::Spec.new do |s|
  s.name                        = "VirgilCrypto"
  s.version                     = "3.0.0"
  s.summary                     = "Contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signatures."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.cocoapods_version           = ">= 0.36"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.author                      = { "Oleksandr Deundiak" => "deundiak@gmail.com" }
  s.platforms                   = { :ios => "8.0", :osx => "10.10", :tvos => "9.0", :watchos => "2.0" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.module_name                 = "VirgilCrypto"
  s.source_files                = "Source/**/*.{h,m}"
  s.public_header_files         = "Source/*.h",
                                  "Source/pfs/*.h"
  s.requires_arc                = true
  s.library                     = 'stdc++'
  s.ios.vendored_frameworks     = "CryptoLib/iOS/VSCCrypto.framework"
  s.osx.vendored_frameworks     = "CryptoLib/macOS/VSCCrypto.framework"
  s.tvos.vendored_frameworks    = "CryptoLib/tvOS/VSCCrypto.framework"
  s.watchos.vendored_frameworks = "CryptoLib/watchOS/VSCCrypto.framework"
  s.xcconfig                    = { "HEADER_SEARCH_PATHS" => "$(FRAMEWORK_SEARCH_PATHS)/VSCCrypto.framework/Headers" }
end
