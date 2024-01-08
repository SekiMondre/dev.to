It's a new year! And to start working on my new year resolutions (I made none), I decided to write an awesome article (it's actually a basic tutorial) on this great day (it's nighttime).

Let's face it: we spend more time of our lives in the digital world than in the "real" world. The fact is that the internet is just a reflection of our tangible reality: In the same fashion that our grandparents would put a letter addressed to someone inside an envelope – to make it opaque to meddling observers while in transport –, in the era of light-speed communication, we had to figure out our own way of protecting the messages that are travelling through the wire.

End-to-end encryption is an invaluable tool to protect information and ensure secure communication. We're gonna cover how to establish a secure channel between two peers in which we can send obfuscated messages.

## Crypto Attack: Getting Started

Before starting, we're gonna need a list of materials that can be found in any basic modern home:

- An elliptic curve.
- A cryptographic cypher.
- A key derivation function.
- ~~A pair of blunt scissors~~

Luckily, Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) got us covered! This will be our tool of choice to handle the heavy lifting on cryptography. Another option available, suitable for cross-platform or server deployment, is [Swift Crypto](https://github.com/apple/swift-crypto). Just don't implement you own cryptographic algorithms, unless you absolutely know what you're doing (chances are you would have a PhD in mathematics).

## Symmetric Cryptography

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
let decryptedMessage = try! cipher.decrypt(ciphertext, with: symmetricKey)!

// Print the ciphertext in a "readable" format
print(String(data: ciphertext, encoding: .ascii)!.debugDescription)
print(decryptedMessage)
```

It should output something like this:

```
"û#ÿ\u{1B}²\u{15}*ÝåÍGy\u{06}¬ý\"ej½¾0b6Û3\u{19}ÇG÷ÍGÍ$Ò^Sãé"
I'm a l33t h4x0r!
```

As it can be verified, the ciphertext, when represented as an ASCII string, looks like random gibberish. However, decrypting it gives back our original message, intact.

### The P2P Key Exchange Problem

If two parties are communicating over encryption, both need to have the same shared key. Thus, the key needs to be shared securely, or else a third actor that intercepts the key can easily break the encryption.

One option is to share it via physical means, like in the good ol' days. But it's easy to see how impractical this would be for anything beyond your neighborhood.

Enter asymmetric cryptography: Instead of using a single key, a key pair composed of a private and a public key will do the job. The private key is kept, well... *private*, while the public key is shared with the other party, as part of a [key agreement](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

## The Diffie-Hellman Key Exchange

Through some [very clever mathematical shenanigans](https://www.youtube.com/watch?v=Yjrfm_oRO0w), the same shared secret can be derived by combining the private and public keys of both parties. This aims to avoid leaking out any sensitive data, as openly distributing the public key does not compromise security, as long as the private key is stored safely. Hence, only the public key needs to be sent to the other party.

To achieve that, we are going to use [elliptic-curve cryptography](https://www.youtube.com/watch?v=NF1pwjL9-DE) (ECC) to create our keypairs. More precisely, we'll use the **X25519** elliptic curve function, which is conveniently implemented by `CryptoKit`. So, let's create a `Peer` object to hold the keys:

```swift
import Foundation
import CryptoKit

// Convenience typealias to abstract the Curve25519 type
typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
typealias PublicKey = Curve25519.KeyAgreement.PublicKey

class Peer {
    
    let name: String
    private let privateKey: PrivateKey
    var publicKey: PublicKey { privateKey.publicKey }
    
    init(name: String, privateKey: PrivateKey) {
        self.name = name
        self.privateKey = privateKey
    }
}
```

Only a private key needs to be created, as the corresponding public key can always be regenerated from it.

We need to create two peers to perform the key agreement: Let's call them **A** and **B**. But **A** and **B** are boring names, and we can do better than that, so let's embrace tradition and call them **A**lice and **B**ob.

```swift
func makePeer(_ name: String) -> Peer {
    let privateKey = PrivateKey()
    return Peer(name: name, privateKey: privateKey)
}

let alice = makePeer("Alice")
let bob = makePeer("Bob")
```

### Shared secret key derivation

Each peer needs to be able to receive the counterpart's public key and create a shared secret using its own private key. Let's write this functionality inside our `Peer` class:

```swift
private(set) var symmetricKey: SymmetricKey?

func deriveSymmetricKey(with publicKey: PublicKey) throws {
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    let sharedKey = sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: Data(),
        outputByteCount: 32)
    self.symmetricKey = sharedKey
}
```

There are two things happening in here: 
1. A shared secret is being created.
2. A symmetric key is derived from the shared secret.

If Alice is receiving Bob's public key, Alice's private key will consume Bob's public key to create a shared secret, and vice versa. Both Alice and Bob shared secrets will be *exactly the same*.

The shared secret, however, is not suitable as a symmetric key. It is still somewhat mathematically imprinted to the elliptic curve used to generate the keys, so we need to introduce more entropy and randomness by using a [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF).

The shared secret's `hkdfDerivedSymmetricKey` function expects 4 parameters:
1. A hash function to use for key derivation. In our case: `SHA256`;
2. A salt value;
3. A context-specific shared info (SI);
4. The key's output size. We want a 256-bit key, so we pass 32 bytes.

Salting and SI are beyond of our scope in here, so we just pass an empty `Data()` buffer for both – which means we will *always* derive the *same symmetric key* given the *same shared secret* – but a key derivation function can be used to derive multiple keys from the same master key by introducing salting and context-specific shared info as its input parameters.

#### Salting
A **salt** is a pseudorandom value that adds entropy to the key derivation process, enhancing its security and preventing, for example, *Rainbow Table attacks* using precomputed hashes to break the key.

#### Shared Info
An optional shared info input allows for the inclusion of additional data to be mixed into key derivation, so that multiple different keys can be derived from the same master key for contexts-specific uses within the same application.

---

Then, we just perform the key agreement:

```swift
try alice.deriveSymmetricKey(with: bob.publicKey)
try bob.deriveSymmetricKey(with: alice.publicKey)
```

## Sending an encrypted payload

Before we continue, let's improve our cipher to encrypt any kind of `Codable` object:

```swift
protocol Cipher {
    func encrypt<T: Codable>(_ payload: T, with symmetricKey: SymmetricKey) throws -> Data
    func decrypt<T: Codable>(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> T
}

struct ChaChaCipher: Cipher {
    
    func encrypt<T: Codable>(_ payload: T, with symmetricKey: SymmetricKey) throws -> Data {
        let data = try JSONEncoder().encode(payload)
        let sealedBox = try ChaChaPoly.seal(data, using: symmetricKey)
        return sealedBox.combined
    }
    
    func decrypt<T: Codable>(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> T {
        let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
        let data = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        return try JSONDecoder().decode(T.self, from: data)
    }
}
```

Now, we put it all together to execute the whole operation:
1. Create Alice and Bob peers;
2. Perform the key agreement;
3. Encode a payload using Alice's key;
4. Decode the payload using Bob's key.

```swift
struct Payload: Codable {
    let message: String
}

let alice = makePeer("Alice")
let bob = makePeer("Bob")

do {
    print("Exchanging keys...")
    try alice.deriveSymmetricKey(with: bob.publicKey)
    try bob.deriveSymmetricKey(with: alice.publicKey)
    
    let payload = Payload(message: "I'm a l33t h4x0r!")
    let cipher = ChaChaCipher()
    
    print("Encoding message: \(payload.message)")
    let ciphertext = try cipher.encrypt(payload, with: alice.symmetricKey!)
    print("Ciphertext: \(String(data: ciphertext, encoding: .ascii)!.debugDescription)")
    
    let decoded: Payload = try cipher.decrypt(ciphertext, with: bob.symmetricKey!)
    print("Decoded message: \(decoded.message)")
} catch {
    print("Error: \(error)")
}
```

Running the code above should output the following result:

```
Exchanging keys...
Encoding message: I'm a l33t h4x0r!
Ciphertext: "dÄz|(:¿|ª\\ì¹A¸U\u{13}áï)´ÿÎ?¤Jó®\u{13}IÈÒ\tß4A.¾ùÜ¿¡\u{1E}àªh¹ùñ[í"
Decoded message: I'm a l33t h4x0r!
```

And voilá, it is done. A very simple end-to-end encryption model working to safeguard the communication between Alice and Bob.

## Going Beyond the Basics

- A private key can be persisted between sessions of an app, so that it can be reused, and it should be stored it securely, if so. The best option on iOS is to use the [Keychain service](https://developer.apple.com/documentation/security/keychain_services).

- There's no guarantee that a message won't be changed before reaching its destination. A [message authentication code](https://en.wikipedia.org/wiki/Message_authentication_code) (MAC) can be introduced to allow a recipient to verify its authenticity and integrity.

- When communicating through a public network, a malicious actor can frontrun the key agreement response with a [man-in-the-middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attack. A robust encryption model must prevent this possibility.

- Reusing the same shared key for all messages means that, if the key is stolen, all future messages are compromised. More advanced encryption models implement some sort of [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) to prevent this from happening.