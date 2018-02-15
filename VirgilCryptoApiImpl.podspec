Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoApiImpl"
  s.version                     = "3.0.0-beta2"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains implementation of VirgilCryptoAPI using VirgilCrypto library."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-foundation-x"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-foundation-x.git", :tag => s.version }
  s.ios.deployment_target       = "8.0"
  s.osx.deployment_target       = "10.10"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source_files                = "VirgilCryptoApiImpl/**/*.swift"
  s.dependency 'VirgilCryptoAPI', '= 1.0.0'
  s.dependency 'VirgilCrypto', '= 3.0.0-beta2'
end
