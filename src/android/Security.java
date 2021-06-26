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

import org.apache.cordova.CallbackContext;

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


    public byte[] generateCipher(byte[] devicePublicKey, byte[] deviceRandom, CallbackContext callbackContext) throws RuntimeException {
        
    	String inputInfo = " -- DPK: " + devicePublicKey.length + " DR: " + deviceRandom.length + " PK: " + this.privateKey.length;
    	
    	try {
           byte[] sharedKey = X25519.computeSharedSecret(this.privateKey, devicePublicKey);

            if (this.proofOfPossession.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA256");
                md.update(this.proofOfPossession);
                byte[] digest = md.digest();
                inputInfo += " DG: " + digest.length;
                sharedKey = xor(sharedKey, digest);
                inputInfo += " SK: " + sharedKey.length;
            }

            IvParameterSpec ivParameterSpec = new IvParameterSpec(deviceRandom);
            SecretKeySpec secretKeySpec = new SecretKeySpec(sharedKey, 0, sharedKey.length, "AES");

            this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
            this.cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            this.clientVerify = this.encrypt(devicePublicKey);
            
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            callbackContext.error(e.getMessage() + inputInfo);
        } catch (NoSuchAlgorithmException e) {
        	 e.printStackTrace();
        	 callbackContext.error(e.getMessage() + inputInfo);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            callbackContext.error(e.getMessage() + inputInfo);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            callbackContext.error(e.getMessage() + inputInfo);
        } catch (Exception e) {
        	callbackContext.error(e.getMessage() + inputInfo);
        }
        
        return this.clientVerify;
    }

    public byte[] generateKeyPair() throws InvalidKeyException {
        this.privateKey = X25519.generatePrivateKey();
        this.publicKey = X25519.publicFromPrivate(this.privateKey);
        return this.publicKey;
    }

    public byte[] encrypt(byte[] data) {
        return this.cipher.update(data);
    }

    public byte[] decrypt(byte[] data) {
        return this.cipher.update(data);
    }
}
