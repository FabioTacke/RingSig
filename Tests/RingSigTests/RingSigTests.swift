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
    XCTAssertEqual(RingSig.commonB(publicKeys: publicKeys).bitWidth, 256)
    
    publicKeys.append(RSA.PublicKey(n: BigUInt(2).power(96) - 1))
    XCTAssertEqual(RingSig.commonB(publicKeys: publicKeys).bitWidth, 256)
  }
  
  func testHashing() {
    let message = BigUInt("Hello, World!".data(using: .utf8)!)
    let digest = RingSig.calculateDigest(message: message)
    XCTAssertEqual(digest.serialize().toHexString(), "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
  }
  
  func testG() {
    let publicKey = RSA.PublicKey(n: 35)
    let commonMod = RingSig.commonB(publicKeys: [publicKey])
    let y = RingSig.g(x: 75, publicKey: publicKey, commonModulus: commonMod)
    XCTAssertEqual(y, 80)
  }
  
  func testInverseG() {
    let privateKey = BigUInt("20870137355527743369994722947712256421")!
    let publicKey = RSA.PublicKey(n: BigUInt("74129651068734579023650285894982581637")!)
    let keyPair = RSA.KeyPair(privateKey: privateKey, publicKey: publicKey)
    let commonMod = RingSig.commonB(publicKeys: [publicKey])
    
    // Choose for x a random value with b bits where b = commonMod.width
    let x = BigUInt("21983811768245934506376641934698562702052075606785051086704688378747977445689082037367759437015074342714318969447746")!
    let y = RingSig.g(x: x, publicKey: publicKey, commonModulus: commonMod)
    let yInverse = RingSig.gInverse(y: y, keyPair: keyPair)
    XCTAssertEqual(x, yInverse)
  }
  
  func testEncryption() {
    let key = BigUInt(2).power(256) - 1
    XCTAssertEqual(key.bitWidth, 256)
    let message = BigUInt(2).power(128) - 1
    XCTAssertEqual(message.bitWidth, 128)
    
    let cipher = RingSig.encrypt(message: message.bytesWithPadding(to: 64), key: key)
    let plaintext = RingSig.decrypt(cipher: cipher.bytesWithPadding(to: 64), key: key)
    XCTAssertEqual(plaintext, message)
  }
  
  func testExample() {
    let signerKeyPair = RSA.KeyPair(privateKey: BigUInt("30423901813523083734702429796436866913")!, publicKey: RSA.PublicKey(n: BigUInt("43400183996187852930492884648088438479")!))
    let nonSignersPublicKeys = [RSA.PublicKey(n: BigUInt("11243439923812814746157156802640116157")!), RSA.PublicKey(n: BigUInt("100957337523025685661252860292428312189")!)]
    let message = "Hello, World!"
    
    let signature = RingSig.ringSign(message: message.data(using: .utf8)!, nonSignersPublicKeys: nonSignersPublicKeys, signerKeyPair: signerKeyPair)
    XCTAssert(RingSig.ringSigVerify(message: message.data(using: .utf8)!, signature: signature))
  }
}
