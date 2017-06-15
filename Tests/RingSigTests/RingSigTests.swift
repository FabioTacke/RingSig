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
  
  func testModulusCalculation() {
    var publicKeys = [RSA.PublicKey(n: BigUInt(234)), RSA.PublicKey(n: BigUInt(567)), RSA.PublicKey(n: BigUInt(123))]
    XCTAssertEqual(RingSig.commonB(publicKeys: publicKeys), BigUInt(256))
    
    publicKeys.append(RSA.PublicKey(n: BigUInt(2).power(96) - 1))
    XCTAssertEqual(RingSig.commonB(publicKeys: publicKeys), BigUInt(256))
  }
  
  func testHashing() {
    let message = BigUInt("Hello, World!".data(using: .utf8)!)
    let digest = RingSig.calculateDigest(message: message)
    XCTAssertEqual(digest.serialize().toHexString(), "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
  }
  
  func testG() {
    let publicKey = RSA.PublicKey(n: 35)
    let y = RingSig.g(x: 75, publicKey: publicKey, modulus: 128)
    XCTAssertEqual(y, 80)
  }
  
  func testEncryption() {
    let key = BigUInt(2).power(256) - 1
    XCTAssertEqual(key.width, 256)
    let message = BigUInt(2).power(128) - 1
    XCTAssertEqual(message.width, 128)
    
    let cipher = RingSig.encrypt(message: message, key: key)
    let plaintext = RingSig.decrypt(cipher: cipher, key: key)
    XCTAssertEqual(plaintext, message)
  }
}
