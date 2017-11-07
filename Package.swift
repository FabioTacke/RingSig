// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "RingSig",
    products: [
      .library(
        name: "RingSig",
        targets: ["RingSig"]),
  ],
    dependencies: [
      .package(url: "https://github.com/lorentey/BigInt.git", .branch("master")),
      .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .branch("master"))
  ],
    targets: [
      .target(
        name: "RingSig",
        dependencies: ["BigInt", "CryptoSwift"]),
      .testTarget(
        name: "RingSigTests",
        dependencies: ["RingSig"]),
  ]
)
