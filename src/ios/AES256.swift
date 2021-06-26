import CommonCrypto;

@objc(AES256) class AES256 : CDVPlugin {

    private var security: AESSecurity
    private static let aes256Queue = DispatchQueue(label: "AESQUEUE", qos: DispatchQoS.background, attributes: .concurrent)

    // Encrypts the plain text using aes256 encryption alogrithm
    @objc(encrypt:) func encrypt(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            var pluginResult = CDVPluginResult(
                status: CDVCommandStatus_ERROR,
                messageAs: "Error occurred while performing Encryption"
            )
            let value = command.arguments[0] as? Data ?? nil
            let encrypted = security.encrypt(value)
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: encrypted)
            self.commandDelegate!.send(
                pluginResult,
                callbackId: command.callbackId
            )
        }
    }

    // Decrypts the aes256 encoded string into plain text
    @objc(decrypt:) func decrypt(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            var pluginResult = CDVPluginResult(
              status: CDVCommandStatus_ERROR,
              messageAs: "Error occurred while performing Decryption"
            )
            let value = command.arguments[0] as? Data ?? nil
            let decrypted = security.decript(value)
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: decrypted)
            self.commandDelegate!.send(
              pluginResult,
              callbackId: command.callbackId
            )
        }
    }
    
    // Constructs security and generates key pair object
    @objc(generateKeyPair:) func generateKeyPair(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            var pluginResult = CDVPluginResult(
              status: CDVCommandStatus_ERROR,
              messageAs: "Error occurred while generating key pair"
            )
            security = AESSecurity()
            let publicKey = security.generateKeyPair()
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: publicKey)
            self.commandDelegate!.send(
              pluginResult,
              callbackId: command.callbackId
            )
        }
    }
    
    // Constructs security and generates key pair object
    @objc(generateCipher:) func generateCipher(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            var pluginResult = CDVPluginResult(
              status: CDVCommandStatus_ERROR,
              messageAs: "Error occurred while generating Cipher"
            )
            let devicePublicKey = command.arguments[0] as? Data ?? nil
            let deviceRandom = command.arguments[0] as? Data ?? nil
            let clientVerify = security.generateCipher(devicePublicKey, deviceRandom)
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: clientVerify)
            self.commandDelegate!.send(
              pluginResult,
              callbackId: command.callbackId
            )
        }
    }

}
