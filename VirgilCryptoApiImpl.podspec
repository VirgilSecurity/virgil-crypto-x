Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoApiImpl"
  s.version                     = "0.9.0"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains basic classes for creating key pairs, encrypting/decrypting data, signing data and verifying signatures."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.platforms                   = { :ios => "8.0" } #, :osx => "10.10", :tvos => "9.0", :watchos => "2.0" }
  s.source_files                = "VirgilCryptoApiImpl/**/*.swift"
  s.dependency 'VirgilCryptoAPI', '~> 0.9'
  s.dependency 'VirgilCrypto', '~> 2.4'
end
