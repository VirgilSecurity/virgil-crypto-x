gem install jazzy

jazzy \
--author "Virgil Security" \
--author_url "https://virgilsecurity.com/" \
--xcodebuild-arguments -scheme,"VirgilCrypto macOS" \
--module "VirgilCrypto" \
--output "${OUTPUT}" \
--hide-documentation-coverage \
--theme apple
