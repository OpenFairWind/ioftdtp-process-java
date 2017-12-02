import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import mjson.Json;

/**
 * Created by marioruggieri on 18/05/2017.
 */
public class TLS {

    private Decryptor decryptor;
    private DigitalSignValidator digitalSignValidator;

    public TLS(String destPrivateKey, String obfuscatedKey, String IV, String srcPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchProviderException {

        // get publicKey from string
        PublicKey srcPBK = stringToPublicKey(srcPublicKey);

        // get privateKey from string
        PrivateKey destPRK = stringToPrivateKey(destPrivateKey);

        // get iv from string
        IvParameterSpec iv = stringToIV(IV);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        decryptor = new Decryptor(destPRK,obfuscatedKey,iv);
        digitalSignValidator = new DigitalSignValidator(srcPBK);
    }

    public Json unobfuscate(String obfuscated) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        String jsonAsString = decryptor.decrypt(obfuscated);
        return Json.read(jsonAsString);
    }

    public boolean verify(String signature, Json json) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        String data = json.toString();
        return digitalSignValidator.verify(signature,data);
    }

    private PublicKey stringToPublicKey(String pbk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // decode from string to binary[]
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(pbk));
        // generate a PublicKey object from the binary array
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private PrivateKey stringToPrivateKey(String pvk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec specPriv = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pvk));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(specPriv);
    }

    private IvParameterSpec stringToIV(String IV) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedIV = Base64.getDecoder().decode(IV);
        return new IvParameterSpec(decodedIV);
    }

}
