import mjson.Json;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Created by marioruggieri on 18/05/2017.
 */

public class DigitalSignValidator {

    private Cipher RSACipher;
    private final static String RSA = "RSA/None/OAEPWithSHA1AndMGF1Padding";
    private final static String provider = "BC";

    public DigitalSignValidator(PublicKey RSAKey) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, NoSuchProviderException {
        // RSA decryptor
        RSACipher = Cipher.getInstance(RSA,provider);
        RSACipher.init(Cipher.DECRYPT_MODE, RSAKey);
    }

    public boolean verify(String signature, String data) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        String tag = unobfuscate(signature);
        String localTag = sha256(data);

        if (tag.equals(localTag))
            return true;

        return false;
    }

    private String unobfuscate(String obfuscated) throws BadPaddingException, IllegalBlockSizeException {
        return Base64.getEncoder().encodeToString(RSACipher.doFinal(Base64.getDecoder().decode(obfuscated)));
    }

    private String sha256(String s) {
        final String SHA = "SHA-256";
        try {
            // Create sha256 Hash
            MessageDigest digest = MessageDigest.getInstance(SHA);
            digest.update(s.getBytes());
            byte messageDigest[] = digest.digest();

            return Base64.getEncoder().encodeToString(messageDigest);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

}
