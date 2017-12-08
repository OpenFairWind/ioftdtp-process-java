import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSAKeysGenerator {

    public static void main(String[] args) throws Exception {
        if (args.length==2) {
		String privateKeyPath=args[0];
		String publicKeyPath=args[1];
        	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        	kpg.initialize(1024); // 1024 is the keysize.
        	KeyPair kp = kpg.generateKeyPair();
        	PublicKey pubk = kp.getPublic();
        	PrivateKey prvk = kp.getPrivate();

        	storeKey(prvk,privateKeyPath);
        	storeKey(pubk,publicKeyPath);
	} else {
          // Usage...
	}
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
