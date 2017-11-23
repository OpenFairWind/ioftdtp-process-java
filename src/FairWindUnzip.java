import java.io.*;
import java.security.*;

import mjson.Json;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;


public class FairWindUnzip {
    private Logger log = Logger.getLogger(FairWindLicense.class.getName());
    private static final String LOG_TAG = "FairWindUnzip";


    public static void main(String[] args) throws IOException {

        String applicationId = "it.uniparthenope.fairwind";
        String userId = "fairwinduser@fairwindsystem.com";
        String deviceId = "8134E3DDFF23F8C40D990707CC9B3C86";
        String filePath = "";
        String destPrivateKeyFolder = "HERE_PATH_TO_PRIVATE_KEY";
        String srcPublicKeyFolder = "HERE_PATH_TO_SRC_PUBLIC_KEY";

        String signerId = args[0];
        String signerPassword = args[1];
        userId = args[2];
        deviceId = args[3];
        filePath = args[4];

        Json jsonOutput = Json.object();
        jsonOutput.set("status", "fail");

        FairWindLicense fairWindLicense = new FairWindLicense();
        if (fairWindLicense != null) {

            if (fairWindLicense.authenticate(signerId, signerPassword) == false) {
                System.exit(-1);
            }

            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String dataAsString = br.readLine();
            br.close();

            Json jsonPack = null;
            Json jsonMiddlePack = null;
            try {
                jsonMiddlePack = Json.read(dataAsString);
                String dataPack = jsonMiddlePack.at("dataPack").asString();
                String obfuscatedAESKey = jsonMiddlePack.at("key").asString();
                String IV = jsonMiddlePack.at("IV").asString();

                // get destination (local) private key
                br = new BufferedReader(new FileReader(destPrivateKeyFolder));
                String destPrivateKey = br.readLine();
                br.close();

                // get src public key
                br = new BufferedReader(new FileReader(srcPublicKeyFolder));
                String srcPublicKey = br.readLine();
                br.close();

                // generate TLS layer
                TLS tls = new TLS(destPrivateKey,obfuscatedAESKey,IV,srcPublicKey);

                // retrieve unobfuscated data
                jsonPack = tls.unobfuscate(dataPack);

                // retrieve signature
                String signature = jsonPack.at("signature").toString();
                signature = signature.replace("\"","");

                // generate json with data
                Json jsonData = Json.object();
                Json data = JsonGZipper.decompress(jsonPack.at("data").asString());
                //System.out.println(jsonPack.at("data"));
                jsonData.set("data", data);

                // verify if hash of received json is equal to the hash received
                if (tls.verify(signature, jsonData)) {
                    jsonOutput = jsonData;
                    jsonOutput.set("status", "success");
                } else {
                    jsonOutput.set("message", "Invalid signature.");
                }
            } catch (BadPaddingException ex) {
                jsonOutput.set("message", ex.getMessage());
            } catch (IllegalBlockSizeException ex) {
                jsonOutput.set("message", ex.getMessage());
            } catch (NoSuchAlgorithmException ex) {
                jsonOutput.set("message", ex.getMessage());
            } catch (InvalidKeyException ex) {
                jsonOutput.set("message", ex.getMessage());
            } catch (InvalidAlgorithmParameterException ex) {
                jsonOutput.set("message", ex.getMessage());
            } catch (NoSuchPaddingException ex) {
                jsonOutput.set("message", ex.getMessage());
            } catch (InvalidKeySpecException ex) {
                jsonOutput.set("message", ex.getMessage());
            }
        }
        System.out.println(jsonOutput.toString());
    }
}
