brew update;
brew outdated carthage || brew upgrade carthage;
carthage build --use-xcframeworks --no-skip-current;

# TODO: Should be replaced by carthage archive, when it supports xcframeworks
zip -r VirgilSDK.xcframework.zip Carthage/Build/VirgilCrypto.xcframework
