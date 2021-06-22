package com.ideas2it.aes256;

import com.google.crypto.tink.subtle.X25519;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 */
public class Security {

    private byte[] privateKey = null;
    private byte[] publicKey = null;
    private byte[] proofOfPossession = null;
    private byte[] clientVerify = null;

    private Cipher cipher;

    /***
     * Create Security implementation
     */
    public Security() {
        this.proofOfPossession = "abcd1234".getBytes();
    }
    
    private byte[] xor(byte[] first, byte[] second) {
        int maxLen = Math.max(first.length, second.length);
        byte[] output = new byte[maxLen];

        for (int i = 0; i < maxLen; i++) {
            int ordA = (int) first[(i % first.length)];
            int ordB = (int) second[(i % second.length)];
            output[i] = (byte) (ordA ^ ordB);
        }

        return output;
    }


    public byte[] generateCipher(byte[] devicePublicKey, byte[] deviceRandom) throws RuntimeException {
        try {
           byte[] sharedKey = X25519.computeSharedSecret(this.privateKey, devicePublicKey);

            if (this.proofOfPossession.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA256");
                md.update(this.proofOfPossession);
                byte[] digest = md.digest();
                sharedKey = xor(sharedKey, digest);
            }

            IvParameterSpec ivParameterSpec = new IvParameterSpec(deviceRandom);
            SecretKeySpec secretKeySpec = new SecretKeySpec(sharedKey, 0, sharedKey.length, "AES");

            this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
            this.cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            this.clientVerify = this.encrypt(devicePublicKey);
        } catch (InvalidKeyException e) {
            Log.e(TAG, e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, e.getMessage());
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        
        return this.clientVerify;
    }

    private void generateKeyPair() throws InvalidKeyException {
        this.privateKey = X25519.generatePrivateKey();
        this.publicKey = X25519.publicFromPrivate(this.privateKey);
    }

    public byte[] encrypt(byte[] data) {
        return this.cipher.update(data);
    }

    public byte[] decrypt(byte[] data) {
        return this.cipher.update(data);
    }
}
