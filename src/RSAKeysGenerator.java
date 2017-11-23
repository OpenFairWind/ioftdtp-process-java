import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSAKeysGenerator {

    public static void main(String[] unused) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // 2048 is the keysize.
        KeyPair kp = kpg.generateKeyPair();
        PublicKey pubk = kp.getPublic();
        PrivateKey prvk = kp.getPrivate();

        storeKey(prvk,"HERE_PATH_TO_PRIVATE_KEY");
        storeKey(pubk,"HERE_PATH_TO_PUBLIC_KEY");
    }

    private static void storeKey(Key key, String path) throws IOException {
        String keystring = keyToString(key);
        PrintWriter pw = new PrintWriter(new File(path));
        pw.write(keystring);
        pw.close();
    }

    private static String keyToString(Key key){
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

}
