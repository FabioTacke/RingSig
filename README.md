# RingSig

The library implements a ring signature scheme in Swift. The algorithm is based on "How to leak a secret" (2001) by Rivest et al.

# What is a ring signature scheme?

When using RSA for message authentication the author of the message creates a signature using their private key. The verifier obtains the signer's public key and checks whether the received message matches the signature. Thus the verifier knows that only someone witch access to the signer's private key could have been creating the signature.

Ring signatures enable the signer to create a signature that doesn't reveal their identity. More precisely the signer bundles their public key alongside the public keys of entities that are not involved at all and uses them for creating the signature. The signature then proves the the verifier that the corresponding message was signed by one of the owners of the public keys. Nevertheless the virifier is not able to tell who exactly is the signer.

## Installation

### Swift Package Manager
`.Package(url: "https://github.com/FabioTacke/RingSig.git", majorVersion: 1)`

### CocoaPods
`pod 'RingSig', '~> 1.0'`

## Usage
```swift
import RingSig

// Generate the signer's RSA keypair
let signerKeyPair = RSA.generateKeyPair()
    
// Generate keypairs for the other participants in the ring signature scheme (i.e. the non-signers)
let nonSignerKeyPairs = [RSA.generateKeyPair(), RSA.generateKeyPair(), RSA.generateKeyPair()]
let nonSignersPublicKeys = nonSignerKeyPairs.map { $0.publicKey }
    
// The message to be signed
let message = "Hello, World!"
    
// Sign the message
let signature = RingSig.ringSign(message: message.data(using: .utf8)!, nonSignersPublicKeys: nonSignersPublicKeys, signerKeyPair: signerKeyPair)
    
// Everybody can now verify that the message was signed by someone of those whose public keys were included in the signature. Still the verifier is not able to tell who of them is the actual signer.
let verified = RingSig.ringSigVerify(message: message.data(using: .utf8)!, signature: signature)
assert(verified)
```

## Disclaimer
The library uses a very basic RSA implementation and therefore shouldn't be considered to offer high crypto security. Furthermore performance was not a design goal when creating the library.
