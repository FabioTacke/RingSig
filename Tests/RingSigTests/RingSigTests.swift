import XCTest
import BigInt
@testable import RingSig

class RingSigTests: XCTestCase {
    func testRSA() {
      let keyPair = RSA.generateKeyPair(length: 64)
      let message = BigUInt("Hello, World!".data(using: .utf8)!)
      let signature = RSA.sign(message: message, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey)
      XCTAssert(RSA.verify(message: message, signature: signature, publicKey: keyPair.publicKey))
    }
}
