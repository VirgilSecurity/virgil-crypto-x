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
  s.requires_arc                = true

  s.subspec 'wrapper' do |ss|
    ss.source_files                = "VirgilCrypto/**/*.{h,mm}"
    ss.public_header_files         = "VirgilCrypto/Source/*.h", "VirgilCrypto/Source/pfs/*.h"
    ss.library                     = 'stdc++'
    ss.ios.vendored_frameworks     = "CryptoLib/iOS/VSCCrypto.framework"
    ss.osx.vendored_frameworks     = "CryptoLib/macOS/VSCCrypto.framework"
    ss.tvos.vendored_frameworks    = "CryptoLib/tvOS/VSCCrypto.framework"
    ss.watchos.vendored_frameworks = "CryptoLib/watchOS/VSCCrypto.framework"
    ss.xcconfig                    = { "HEADER_SEARCH_PATHS" => "$(FRAMEWORK_SEARCH_PATHS)/VSCCrypto.framework/Headers" }
  end

  s.subspec 'api-impl' do |ss|
    ss.source_files                = "VirgilCryptoApiImpl/**/*.swift"
    ss.dependency 'VirgilCrypto/wrapper'
  end
end
