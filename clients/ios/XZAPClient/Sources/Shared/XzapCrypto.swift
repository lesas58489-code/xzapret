import Foundation
import CryptoKit

/// AES-256-GCM encryption compatible with Python XZAPCrypto.
/// Wire format: [12B nonce][ciphertext][16B tag]
struct XzapCrypto {
    let key: SymmetricKey

    init(keyData: Data) {
        precondition(keyData.count == 32, "Key must be 32 bytes")
        self.key = SymmetricKey(data: keyData)
    }

    init(base64Key: String) {
        guard let data = Data(base64Encoded: base64Key) else {
            fatalError("Invalid base64 key")
        }
        self.init(keyData: data)
    }

    func encrypt(_ plaintext: Data) throws -> Data {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        // nonce (12) + ciphertext + tag (16)
        var result = Data(nonce)
        result.append(sealed.ciphertext)
        result.append(sealed.tag)
        return result
    }

    func decrypt(_ data: Data) throws -> Data {
        guard data.count > 28 else { // 12 nonce + 16 tag minimum
            throw XzapError.ciphertextTooShort
        }
        let nonce = try AES.GCM.Nonce(data: data.prefix(12))
        let ciphertext = data[12..<(data.count - 16)]
        let tag = data.suffix(16)
        let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealed, using: key)
    }
}

enum XzapError: Error {
    case ciphertextTooShort
    case frameTooLarge
    case handshakeFailed(String)
    case connectionClosed
    case invalidResponse
}
