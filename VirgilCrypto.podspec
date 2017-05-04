Pod::Spec.new do |s|
  s.name                        = "VirgilCrypto"
  s.version                     = "2.0.9"
  s.summary                     = "Contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signs."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.cocoapods_version           = ">= 0.36"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.author                      = { "Oleksandr Deundiak" => "deundiak@gmail.com" }
  s.platforms                   = { :ios => "7.0", :osx => "10.12" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.module_name                 = "VirgilCrypto"
  s.source_files                = "Source/*"
  s.public_header_files         = "Source/*.h"
  s.private_header_files        = "Source/*Private.h"
  s.requires_arc                = true
  s.library                     = "stdc++"
  s.ios.vendored_frameworks     = "Frameworks/ios/*.framework"
  s.osx.vendored_frameworks     = "Frameworks/macos/*.framework"
  s.xcconfig                    = { "HEADER_SEARCH_PATHS" => "$(FRAMEWORK_SEARCH_PATHS)/VSCCrypto.framework/Headers" }
end
