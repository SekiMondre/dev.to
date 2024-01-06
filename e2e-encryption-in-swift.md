It's a new year! And to start working on my new year resolutions (I made none), I decided to write an awesome article (it's actually a basic tutorial) on this great day (it's nighttime).

Let's face it: we spend more time of our lives in the digital world than in the "real" world. The fact is that the internet is just a reflection of our tangible reality: In the same fashion that our grandparents would put a letter addressed to someone inside an envelope – to make it opaque to meddling observers while in transport –, in the era of light-speed communication, we had to figure out our own way of protecting the messages that are travelling through the wire.

End-to-end encryption is an invaluable tool to protect information and ensure secure communication. We're gonna cover how to establish a secure channel between two peers in which we can send obfuscated messages.

# Crypto Attack: Getting Started

Before starting, we're gonna need a list of materials that can be found in any basic modern home:

- An elliptic curve.
- A cryptographic cypher.
- A key derivation function.
- ~~A pair of blunt scissors~~

Luckily, Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) got us covered! This will be our tool of choice to handle the heavy lifting on cryptography. Another option available, suitable for cross-platform or server deployment, is [Swift Crypto](https://github.com/apple/swift-crypto). Just don't implement you own cryptographic algorithms, unless you absolutely know what you're doing (chances are you would have a PhD in mathematics).

# Symmetric Cryptography

To encrypt a message, you need a key. The encrypted message can be decrypted using the same key. Let's start by defining a simple cipher:

```swift
import Foundation
import CryptoKit

protocol Cipher {
    func encrypt(_ data: String, with symmetricKey: SymmetricKey) throws -> Data
    func decrypt(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> String?
}
```

Now, for the actual encryption, `CryptoKit` provides an implementation of the [ChaChaPoly](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) algorithm, which is a preferred option when running in mobile devices and ARM-based architectures, due to performance concerns.

```swift
struct ChaChaPolyCipher: Cipher {
    
    func encrypt(_ message: String, with symmetricKey: SymmetricKey) throws -> Data {
        let data = message.data(using: .utf8)!
        let sealedBox = try ChaChaPoly.seal(data, using: symmetricKey)
        return sealedBox.combined
    }
    
    func decrypt(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> String? {
        let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
        let data = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        return String(data: data, encoding: .utf8)
    }
}
```

Time to try it out:

```swift
let message = "I'm a l33t h4x0r!"
let symmetricKey = SymmetricKey(size: .bits256) // Create a 256-bit key
let cipher = ChaChaPolyCipher()

let ciphertext = try! cipher.encrypt(message, with: symmetricKey)
print(String(data: ciphertext, encoding: .ascii)!) // Print ciphertext as an ascii string

let decryptedMessage = try! cipher.decrypt(ciphertext, with: symmetricKey)!
print(decryptedMessage)
```

It should print something like this:

```
Rª[sëHãª¬äá½`¥Â£UÅQwQiñÊD¿¦faé±	Î
I'm a l33t h4x0r!
```

As it can be verified, the ciphertext, when represented as an ASCII string, looks like gibberish. However, decrypting it gives back our message.

### The P2P Key Exchange Problem

If two parties are communicating over encryption, both need to have the same shared key. Thus, the key needs to be shared securely, or else a third actor that intercepts the key can easily break the encryption.

One option is to share it via physical means, like in the good ol' days. But it's easy to see how impractical this would be for anything beyond your neighborhood.

Enter asymmetric cryptography: Instead of using a single key, a key pair composed of a private and a public key will do the job. The private key is kept, well... *private*, while the public key is shared with the other party, as part of a [key agreement](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

# The Diffie-Hellman Key Exchange

Through some [very clever mathematical shenanigans](https://www.youtube.com/watch?v=Yjrfm_oRO0w), the same shared secret can be derived by combining the private and public keys of both parties. This aims to avoid leaking out any sensitive data, as openly distributing the public key does not compromise security, as long as the private key is stored safely.

// use curve25519

// create peers

// improve cipher

// execute agreement