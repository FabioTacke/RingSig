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
  
  public func bytesWithPadding(to bytesCount: Int) -> Array<UInt8> {
    let bytes = self.serialize().bytes
    let paddingBytes = bytesCount - bytes.count
    var padding = Array<UInt8>()
    for _ in 0..<paddingBytes {
      padding += [0]
    }
    return padding + bytes
  }

}
