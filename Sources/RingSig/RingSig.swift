//
//  RingSig.swift
//  RingSig
//
//  Created by Fabio Tacke on 14.06.17.
//
//

import Foundation
import BigInt

class RingSig {
  static func ringSign(message: BigUInt, nonSigneesPublicKeys: [RSA.PublicKey], signeeKeyPair: RSA.KeyPair) -> Signature {
    // Choose a moduli for all the calculations that is sufficiently great
    let b = commonB(publicKeys: nonSigneesPublicKeys + [signeeKeyPair.publicKey])
    
    return Signature(publicKeys: [], glue: BigUInt(), xValues: [])
  }
  
  /// Because all the usual RSA signature calculations use different moduli `n_i`, we need to choose a modulus b that is greater than the greatest modulus n_i.
  /// In particular we are going to choose b to be at least 160 bit greater than the greatest of the `n_i` as suggested in the paper.
  /// Furthermore we might add a few bits more in order to reach a multiple of the block size of the encryption algorithm (in this case 128 bit for AES).
  ///
  /// - Parameter publicKeys: The public keys that specify the individual moduli
  /// - Returns: A modulus that is greater than the greatest `n_i` and a multiple of the AES block size
  private static func commonB(publicKeys: [RSA.PublicKey]) -> BigUInt {
    let nMax = publicKeys.reduce(1) { (result, publicKey) in
      return publicKey.n > result ? publicKey.n : result
    }
    var sufficientBits = BigUInt(nMax.width + 160)
    if sufficientBits % 128 > 0 {
      sufficientBits += 128 - (sufficientBits % 128)
    }
    return sufficientBits
  }
  
  struct Signature {
    let publicKeys: [RSA.PublicKey]
    let glue: BigUInt
    let xValues: [BigUInt]
  }
}
