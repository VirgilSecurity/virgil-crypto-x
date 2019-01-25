gem install jazzy

jazzy \
--author "Virgil Security" \
--author_url "https://virgilsecurity.com/" \
--xcodebuild-arguments -scheme,"VirgilCryptoApiImpl macOS" \
--module "VirgilCryptoApiImpl" \
--output "${VIRGIL_SDK_HTML_PATH_DST}" \
--hide-documentation-coverage \
--theme apple
