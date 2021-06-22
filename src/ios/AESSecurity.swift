import Curve25519
import Foundation

class AESSecurity {
    
    private static let basePoint = Data([9] + [UInt8](repeating: 0, count: 31))

    private var proofOfPossession: Data?
    private var privateKey: Data?
    private var publicKey: Data?
    private var clientVerify: Data?
    private var cryptoAES: CryptoAES?

    private var sharedKey: Data?
    private var deviceRandom: Data?

    /// Create Security implementation with given proof of possession
    ///
    init() {
        self.proofOfPossession = "abcd1234".data(using: .utf8)
        generateKeyPair()
    }

    /// Encrypt data received in argument.
    ///
    /// - Parameter data: Data to be sent.
    /// - Returns: Encrypted data.
    func encrypt(data: Data) -> Data? {
        guard let cryptoAES = self.cryptoAES else {
            return nil
        }
        return cryptoAES.encrypt(data: data)
    }

    /// Decrypt data received in argument.
    ///
    /// - Parameter data: Data to be sent.
    /// - Returns: Decrypted data.
    func decrypt(data: Data) -> Data? {
        guard let cryptoAES = self.cryptoAES else {
            return nil
        }
        return cryptoAES.encrypt(data: data)
    }

    private func generatePrivateKey() -> Data? {
        var keyData = Data(count: 32)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            return nil
        }
    }

    private func generateKeyPair() {
        self.privateKey = generatePrivateKey()
        guard let privateKey = self.privateKey else {
            publicKey = nil
            return
        }
        publicKey = try? Curve25519.publicKey(for: privateKey, basepoint: ESPSecurity1.basePoint)
    }
    
    private func xor(first: Data, second: Data) -> Data {
        let firstBytes = [UInt8](first)
        let secondBytes = [UInt8](second)

        let maxLength = max(firstBytes.count, secondBytes.count)
        var output = [UInt8].init(repeating: 0, count: maxLength)
        for i in 0 ..< maxLength {
            output[i] = firstBytes[i % firstBytes.count] ^ secondBytes[i % secondBytes.count]
        }

        return Data(output)
    }

    /// Processes data received as reponse of Step 0 request.
    ///
    /// - Throws: Security errors.
    private func generateCipher(devicePublicKey: Data, deviceRandom: Data) throws {
        
        do {
            var sharedKey = try Curve25519.calculateAgreement(privateKey: privateKey!, publicKey: devicePublicKey)
            if let pop = self.proofOfPossession, pop.count > 0 {
                let digest = pop.sha256()
                sharedKey = xor(first: sharedKey, second: digest)
            }

            cryptoAES = CryptoAES(key: sharedKey, iv: deviceRandom)

            let verifyBytes = encrypt(data: devicePublicKey)

           
            clientVerify = verifyBytes
        } catch {
           
        }
    }
    
}

