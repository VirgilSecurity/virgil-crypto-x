Pod::Spec.new do |s|
  s.name                        = "VirgilCrypto"
  s.version                     = "2.3.1"
  s.summary                     = "Contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signs."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.cocoapods_version           = ">= 0.36"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.author                      = { "Oleksandr Deundiak" => "deundiak@gmail.com" }
  s.platforms                   = { :ios => "8.0", :osx => "10.10" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.module_name                 = "VirgilCrypto"
  s.source_files                = "Source/**/*.{h,m}"
  s.public_header_files         = "Source/*.h",
                                  "Source/pfs/*.h"
  s.requires_arc                = true
  s.library                     = 'stdc++'
  s.ios.vendored_frameworks     = "CryptoLib/iOS/VSCCrypto.framework"
  s.osx.vendored_frameworks     = "CryptoLib/macOS/VSCCrypto.framework"
  s.xcconfig                    = { "HEADER_SEARCH_PATHS" => "$(FRAMEWORK_SEARCH_PATHS)/VSCCrypto.framework/Headers" }
end
