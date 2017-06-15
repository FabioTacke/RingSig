//
//  RingSig.swift
//  RingSig
//
//  Created by Fabio Tacke on 14.06.17.
//
//

import Foundation
import BigInt
import CryptoSwift

class RingSig {
  static func ringSign(message: BigUInt, nonSigneesPublicKeys: [RSA.PublicKey], signeeKeyPair: RSA.KeyPair) -> Signature {
    // 0. Choose a moduli for all the calculations that is sufficiently great
    let b = commonB(publicKeys: nonSigneesPublicKeys + [signeeKeyPair.publicKey])
    print("b=\(b.description)")
    
    // 1. Compute the key as k = h(m)
    let k = calculateDigest(message: message)
    print("Length of k: \(k.width)")
    
    // 2. Pick a random glue value
    let glue = BigUInt.randomInteger(withExactWidth: b.width)
    
    // 3.
    
    return Signature(publicKeys: [], glue: BigUInt(), xValues: [])
  }
  
  /// Calculates the SHA256 hash digest of the given input.
  ///
  /// - Parameter message: The message whose hash digest is going to be computed
  /// - Returns: SHA256 hash digest of the given message
  internal static func calculateDigest(message: BigUInt) -> BigUInt {
    return BigUInt(message.serialize().sha256())
  }
  
  /// Because all the usual RSA signature calculations use different moduli `n_i`, we need to choose a modulus b that is greater than the greatest modulus n_i.
  /// In particular we are going to choose b to be at least 160 bit greater than the greatest of the `n_i` as suggested in the paper.
  /// Furthermore we might add a few bits more in order to reach a multiple of the block size of the encryption algorithm (in this case 128 bit for AES).
  ///
  /// - Parameter publicKeys: The public keys that specify the individual moduli
  /// - Returns: A modulus that is greater than the greatest `n_i` and a multiple of the AES block size
  internal static func commonB(publicKeys: [RSA.PublicKey]) -> BigUInt {
    let nMax = publicKeys.reduce(1) { (result, publicKey) in
      return publicKey.n > result ? publicKey.n : result
    }
    var sufficientBits = BigUInt(nMax.width + 160)
    if sufficientBits % 128 > 0 {
      sufficientBits += 128 - (sufficientBits % 128)
    }
    return sufficientBits
  }
  
  /// Computes the extended trap-door permutation `g_i` as described in the paper.
  ///
  /// - Parameters:
  ///   - x: Input argument
  ///   - publicKey: The public key holds the modulus needed for the calculation
  ///   - modulus: The modulus `b` is the common modulus used for all the calculations
  /// - Returns: `g(x) = qn+f(r)` where `x = qn+r` and `f(r)` is the RSA encryption operation `r^e`
  internal static func g(x: BigUInt, publicKey: RSA.PublicKey, modulus: BigUInt) -> BigUInt {
    let q = x / publicKey.n
    var result = x
    if (q + 1) * publicKey.n <= BigUInt(2).power(modulus.width) {
      let r = x - (q * publicKey.n)
      let fr = r.power(RSA.PublicKey.e, modulus: publicKey.n)
      result = (q * publicKey.n) + fr
    }
    return result
  }
  
  /// Encrypts the given message under the specified key using AES-256 CBC.
  ///
  /// - Requires: Message length must be a multiple of the block size of 128 bit.
  /// - Parameters:
  ///   - message: The message to be encrypted.
  ///   - key: The (symmetric) key.
  /// - Returns: Ciphertext of AES-256 CBC encrypted message.
  internal static func encrypt(message: BigUInt, key: BigUInt) -> BigUInt {
    precondition(message.width % 128 == 0)
    let aes = try! AES(key: key.serialize().bytes, iv: ">RingSiggiSgniR<".data(using: .utf8)!.bytes, blockMode: .CBC, padding: NoPadding())
    let ciphertext = try! aes.encrypt(message.serialize().bytes)
    return BigUInt(Data(bytes: ciphertext))
  }
  
  /// Decrypts the given ciphertext under the specified key using AES-256 CBC.
  ///
  /// - Parameters:
  ///   - cipher: The ciphertext to be decrypted.
  ///   - key: The (symmetric) key.
  /// - Returns: Plaintext of AES-256 CBC decrypted ciphertext.
  internal static func decrypt(cipher: BigUInt, key: BigUInt) -> BigUInt {
    let aes = try! AES(key: key.serialize().bytes, iv: ">RingSiggiSgniR<".data(using: .utf8)!.bytes, blockMode: .CBC, padding: NoPadding())
    let plaintext = try! aes.decrypt(cipher.serialize().bytes)
    return BigUInt(Data(bytes: plaintext))
  }
  
  struct Signature {
    let publicKeys: [RSA.PublicKey]
    let glue: BigUInt
    let xValues: [BigUInt]
  }
}
