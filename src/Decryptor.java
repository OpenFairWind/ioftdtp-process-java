import java.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import mjson.Json;

/**
 * Created by marioruggieri on 18/05/2017.
 */

public class Decryptor {

    // Asymmetric part
    private Cipher RSACipher;
    private PrivateKey RSAKey;

    // Symmetric part
    private Cipher AESCipher;
    private IvParameterSpec IV;
    private SecretKey AESKey;

    private final static String RSA = "RSA/None/OAEPWithSHA1AndMGF1Padding";   
    private final static String provider = "BC";
    private final static String AES = "AES/CBC/PKCS5Padding";

    public Decryptor(PrivateKey RSAPrivateKey, String obfuscatedAESKey, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        RSAKey = RSAPrivateKey;
        RSACipher = Cipher.getInstance(RSA, provider);
        RSACipher.init(Cipher.DECRYPT_MODE, RSAKey);

        AESKey = unobfuscateKey(obfuscatedAESKey);
        IV = iv;
        AESCipher = Cipher.getInstance(AES);
        AESCipher.init(Cipher.DECRYPT_MODE, AESKey, IV);
    }

    public String decrypt(String obfuscated) throws BadPaddingException, IllegalBlockSizeException {
        return new String(AESCipher.doFinal(Base64.getDecoder().decode(obfuscated)));
    }

    private SecretKey unobfuscateKey(String obfuscatedKey) throws BadPaddingException, IllegalBlockSizeException {
        byte[] key = RSACipher.doFinal(Base64.getDecoder().decode(obfuscatedKey));
        return new SecretKeySpec(key, 0, key.length, "AES");
    }

}
