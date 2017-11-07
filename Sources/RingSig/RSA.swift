//
//  RSA.swift
//  RingSig
//
//  Created by Fabio Tacke on 14.06.17.
//
//

import Foundation
import BigInt

public class RSA {
  public static func generateKeyPair(length: Int = 128) -> KeyPair {
    // Choose two distinct prime numbers
    let p = BigUInt.randomPrime(length: length)
    var q = BigUInt.randomPrime(length: length)
    
    while p == q {
      q = BigUInt.randomPrime(length: length)
    }
    
    // Calculate modulus and private key d
    let n = p * q
    let phi = (p-1) * (q-1)
    let d = PublicKey.e.inverse(phi)!
    
    return KeyPair(privateKey: d, publicKey: PublicKey(n: n))
  }
  
  public static func sign(message: BigUInt, privateKey: PrivateKey, publicKey: PublicKey) -> Signature {
    return message.power(privateKey, modulus: publicKey.n)
  }
  
  public static func verify(message: BigUInt, signature: Signature, publicKey: PublicKey) -> Bool {
    return signature.power(PublicKey.e, modulus: publicKey.n) == message
  }
  
  public struct KeyPair {
    public let privateKey: PrivateKey
    public let publicKey: PublicKey
  }
  
  public struct PublicKey: Hashable {
    public let n: BigUInt
    public static let e = BigUInt(65537)
    
    public var hashValue: Int {
      return n.hashValue
    }
    
    public static func ==(lhs: RSA.PublicKey, rhs: RSA.PublicKey) -> Bool {
      return lhs.n == rhs.n
    }
  }
  
  public typealias PrivateKey = BigUInt
  public typealias Signature = BigUInt
}
