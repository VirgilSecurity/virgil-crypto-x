// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VirgilCrypto",
    platforms: [
        .macOS(.v10_10), .iOS(.v11), .tvOS(.v11), .watchOS(.v4)
    ],
    products: [
        .library(
            name: "VirgilCrypto",
            targets: ["VirgilCrypto"]),
    ],

    dependencies: [
        .package(url: "https://github.com/VirgilSecurity/virgil-cryptowrapper-x.git", exact: .init(0, 16, 3))
    ],

    targets: [
        .target(
            name: "VirgilCrypto",
            dependencies: [
                .product(name: "VirgilCryptoFoundation", package: "virgil-cryptowrapper-x"),
                .product(name: "VirgilCryptoPythia", package: "virgil-cryptowrapper-x"),
                .product(name: "VirgilCryptoRatchet", package: "virgil-cryptowrapper-x")
            ],
            path: "Source"
        ),
        .testTarget(
            name: "VirgilCryptoTests",
            dependencies: ["VirgilCrypto"],
            path: "Tests",
            resources: [
                .process("Data/testData.txt"),
                .process("Data/crypto_compatibility_data.json")
            ],
            swiftSettings: [
                .define("SPM_BUILD")
            ]
        )
    ]
)
