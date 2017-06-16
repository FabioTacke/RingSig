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
  static func ringSign(message: BigUInt, nonSignersPublicKeys: [RSA.PublicKey], signerKeyPair: RSA.KeyPair) -> Signature {
    // 0. Choose a moduli for all the calculations that is sufficiently great
    let commonModulus = commonB(publicKeys: nonSignersPublicKeys + [signerKeyPair.publicKey])
    
    // 1. Compute the key as k = h(m)
    let k = calculateDigest(message: message)
    
    // 2. Pick a random glue value
    let glue = BigUInt.randomInteger(withExactWidth: commonModulus.width)
    
    // 3. Pick random values x_i for the non-signers and compute y_i
    var xValues: [RSA.PublicKey: BigUInt] = [:]
    for publicKey in nonSignersPublicKeys {
      xValues[publicKey] = BigUInt.randomInteger(withExactWidth: commonModulus.width)
    }
    
    let yValues: [BigUInt] = xValues.map { (publicKey, xValue) in
      return g(x: xValue, publicKey: publicKey, commonModulus: commonModulus)
    }
    
    // 4. Solve the ring equation for y_s of the signer
    let yS = solve(arguments: yValues, key: k, glue: glue)
    
    // 5. Invert the signer's trap-door permutation
    let xS = gInverse(y: yS, keyPair: signerKeyPair)
    
    // 6. Shuffle public keys
    xValues[signerKeyPair.publicKey] = xS
    var shuffledPublicKeys = nonSignersPublicKeys + [signerKeyPair.publicKey]
    shuffledPublicKeys.shuffle()
    
    return Signature(publicKeys: shuffledPublicKeys, glue: glue, xValues: shuffledPublicKeys.map { xValues[$0]! })
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
    var sufficientBits = nMax.width + 160
    if sufficientBits % 128 > 0 {
      sufficientBits += 128 - (sufficientBits % 128)
    }
    return BigUInt.randomInteger(withExactWidth: sufficientBits)
  }
  
  /// Computes the extended trap-door permutation `g_i` as described in the paper.
  ///
  /// - Parameters:
  ///   - x: Input argument
  ///   - publicKey: The public key holds the modulus needed for the calculation
  ///   - modulus: The modulus `b` is the common modulus used for all the calculations
  /// - Returns: `g(x) = qn+f(r)` where `x = qn+r` and `f(r)` is the RSA encryption operation `r^e`
  internal static func g(x: BigUInt, publicKey: RSA.PublicKey, commonModulus: BigUInt) -> BigUInt {
    let q = x / publicKey.n
    var result = x
    if (q + 1) * publicKey.n <= commonModulus {
      let r = x - (q * publicKey.n)
      let fr = r.power(RSA.PublicKey.e, modulus: publicKey.n)
      result = (q * publicKey.n) + fr
    }
    return result
  }
  
  /// Computes the inverse function of `g(x)`
  ///
  /// - Parameters:
  ///   - y: The result of the function equation `y = g(x)`
  ///   - keyPair: The key pair of the signer
  /// - Returns: `x` so that `g(x)=y`
  internal static func gInverse(y: BigUInt, keyPair: RSA.KeyPair) -> BigUInt {
    // y = g(x) = q * n + f(r)
    let q = y / keyPair.publicKey.n
    
    // <=> y - q * n = f(r)
    let fr = y - q * keyPair.publicKey.n
    
    // <=> f^{-1}(y - q * n) = r
    let r = fr.power(keyPair.privateKey, modulus: keyPair.publicKey.n)
    
    // x = q * n + r
    return q * keyPair.publicKey.n + r
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
  
  /// Computes the combination function described in the paper.
  ///
  /// - Parameters:
  ///   - arguments: The arguments passed into the function
  ///   - key: The (symmetric) key to be used for the encryption algorithm
  ///   - glue: The chosen glue value
  /// - Returns: Result of the function
  internal static func C(arguments: [BigUInt], key: BigUInt, glue: BigUInt) -> BigUInt {
    var result = glue
    for argument in arguments {
      let plaintext = argument ^ result
      result = encrypt(message: plaintext, key: key)
    }
    return result
  }
  
  /// Solve the ring equation C_k,v(y_1, ..., y_r) = v for y_r
  ///
  /// - Parameters:
  ///   - arguments: The y_i values
  ///   - key: The (symmetric) key used for the encryption algorithm
  ///   - glue: The glue value
  /// - Returns: The computed value for y_r
  internal static func solve(arguments: [BigUInt], key: BigUInt, glue: BigUInt) -> BigUInt {
    let lhs = decrypt(cipher: glue, key: key)
    let rhs = C(arguments: arguments, key: key, glue: glue)
    return lhs ^ rhs
  }
  
  struct Signature {
    let publicKeys: [RSA.PublicKey]
    let glue: BigUInt
    let xValues: [BigUInt]
  }
}
