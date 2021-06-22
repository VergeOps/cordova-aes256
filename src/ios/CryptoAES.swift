import CommonCrypto
import Foundation

class CryptoAES {
    var iv: Data
    var key: Data

    var streamBlock = Data()
    var nonceCounterOffset = 0
    var decryptor: AESDecryptor!

    public init(key: Data, iv: Data) {
        self.key = key
        self.iv = iv
        decryptor = AESDecryptor(key: key, andIV: iv)
    }

    func encrypt(data: Data) -> Data? {
        var returnData: Data?
        var error: NSError?
        returnData = decryptor.cryptData(data, operation: CCOperation(kCCEncrypt), mode: CCMode(kCCModeCTR), algorithm: CCAlgorithm(kCCAlgorithmAES), padding: CCPadding(ccNoPadding), keyLength: kCCKeySizeAES256, iv: iv, key: key, error: &error)
        return returnData
    }
}
