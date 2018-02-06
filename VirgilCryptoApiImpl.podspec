Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoApiImpl"
  s.version                     = "1.0.0"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains implementation of VirgilCryptoAPI using VirgilCrypto library."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.platforms                   = { :ios => "8.0", :osx => "10.10", :tvos => "9.0", :watchos => "2.0" }
  s.source_files                = "VirgilCryptoApiImpl/**/*.swift"
  s.dependency 'VirgilCryptoAPI', '= 1.0.0'
  s.dependency 'VirgilCrypto', '= 3.0.0-beta4'
end
