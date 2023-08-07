carthage build --use-xcframeworks --no-skip-current;

# TODO: Should be replaced by carthage archive, when it supports xcframeworks
zip -r VirgilCrypto.xcframework.zip Carthage/Build/VirgilCrypto.xcframework
