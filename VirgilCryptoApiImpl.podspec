Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoApiImpl"
  s.version                     = "5.0.0-alpha1"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains implementation of VirgilCryptoAPI using VirgilCrypto library."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-crypto-x"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-crypto-x.git", :tag => s.version }
  s.ios.deployment_target       = "9.0"
  s.osx.deployment_target       = "10.10"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source_files                = "Source/**/*.swift"
  s.dependency 'VirgilCryptoAPI', '~> 1.0'
  s.dependency 'VirgilCryptoFoundation', '~> 0.2.0-alpha'
end
