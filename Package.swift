// swift-tools-version:5.9
import PackageDescription

let firebaseSDKVersion: Version = "12.9.0"
let googleSignInVersion: Version = "9.0.0"

let package = Package(
    name: "cordova-plugin-firebasex-auth",
    platforms: [.iOS(.v13)],
    products: [
        .library(
            name: "cordova-plugin-firebasex-auth",
            targets: ["FirebasexAuthPlugin"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apache/cordova-ios.git", branch: "master"),
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", exact: firebaseSDKVersion),
        .package(url: "https://github.com/google/GoogleSignIn-iOS.git", exact: googleSignInVersion),
    ],
    targets: [
        .target(
            name: "FirebasexAuthPlugin",
            dependencies: [
                .product(name: "Cordova", package: "cordova-ios"),
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "GoogleSignIn", package: "GoogleSignIn-iOS"),
            ],
            path: "src/ios",
            publicHeadersPath: "."
        )
    ]
)