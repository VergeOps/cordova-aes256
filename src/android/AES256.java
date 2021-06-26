package com.ideas2it.aes256;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONException;
import org.apache.cordova.CordovaArgs;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import shaded.org.apache.commons.codec.binary.Hex;

/**
 * This class used to perform AES encryption and decryption.
 */
public class AES256 extends CordovaPlugin {

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String GENERATE_CIPHER = "generateCipher";
    private static final String GENERATE_KEY_PAIR = "generateKeyPair";


    private Security security;
    
    @Override
    public boolean execute(final String action, final CordovaArgs args,  final CallbackContext callbackContext) throws JSONException {
        try {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                    	if (GENERATE_CIPHER.equalsIgnoreCase(action)) {
                            byte[] devicePublicKey = args.getArrayBuffer(0);
                            byte[] deviceRandom = args.getArrayBuffer(1);
                            callbackContext.success(security.generateCipher(devicePublicKey, deviceRandom, callbackContext));
                        } else if (ENCRYPT.equalsIgnoreCase(action)) {
                            byte[] value = args.getArrayBuffer(0);
                            callbackContext.success(security.encrypt(value));
                        } else if (DECRYPT.equalsIgnoreCase(action)) {
                            byte[] value = args.getArrayBuffer(0);
                            callbackContext.success(security.decrypt(value));
                        } else if (GENERATE_KEY_PAIR.equalsIgnoreCase(action)) {
                        	security = new Security();
                            callbackContext.success(security.generateKeyPair());
                        } else {
                            callbackContext.error("Invalid method call");
                        }
                    } catch (Exception e) {
                        System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
                        callbackContext.error("Error occurred while performing " + action);
                    }
                }
            });
        } catch (Exception e) {
            System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error occurred while performing " + action);
        }
        return  true;
    }
}
