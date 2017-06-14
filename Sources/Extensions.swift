//
//  Extensions.swift
//  RingSig
//
//  Created by Fabio Tacke on 14.06.17.
//
//

import Foundation
import BigInt

extension BigUInt {
  
  public static func randomPrime(length: Int) -> BigUInt {
    var random = BigUInt.randomInteger(withMaximumWidth: length)
    
    while !random.isPrime() {
      random = BigUInt.randomInteger(withMaximumWidth: length)
    }
    
    return random
  }
}
