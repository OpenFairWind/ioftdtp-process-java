import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.GeneralSecurityException;
import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;
import mjson.Json;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.FileReader;
import java.io.BufferedReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Date;
import java.util.TimeZone;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.text.ParseException;

import java.net.InetAddress;
import java.net.UnknownHostException;

import mjson.Json;

public class FairWindLicense {
	private Logger log = Logger.getLogger(FairWindLicense.class.getName());
    	private static final String LOG_TAG = "FairWindUnzip";

	public boolean authenticate(String signerId, String signerPassword){
        	return true;
  	}

	public static void main(String[] args) throws Exception {
        	if (args.length!=4) {
                	System.out.println("Usage: signerId signerPassword userId deviceId");
                	System.exit(-1);
        	}

        	String applicationId="it.uniparthenope.fairwind";
        	String userId="fairwinduser@fairwindsystem.com";
        	String deviceId="8134E3DDFF23F8C40D990707CC9B3C86";

        	String signerId=args[0];
        	String signerPassword=args[1];
        	userId=args[2];
        	deviceId=args[3];


        	FairWindLicense fairWindLicense=new FairWindLicense();

        	if (fairWindLicense.authenticate(signerId,signerPassword)==false) {
                	System.exit(-1);
        	}

        	TimeZone tz = TimeZone.getTimeZone("UTC");
        	DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mmZ");
        	df.setTimeZone(tz);
        	String nowAsISO = df.format(new Date());
        	Date expiresDate = df.parse("2018-12-31T00:00+0000");
        	String expiresAsISO = df.format(expiresDate);


        	InetAddress addr = java.net.InetAddress.getLocalHost();
        	String issuer=addr.getHostName()+"/"+signerId;

        	Json json=Json.object();
        	json.set("userid",userId);
        	json.set("deviceid",deviceId);
        	json.set("timestamp",nowAsISO);
        	json.set("issuer",issuer);
        	json.set("expires",expiresAsISO);
        	json.set("usbserial",true);
        	json.set("signalkclient",true);
       		json.set("tcpipclient",true);
        	json.set("bluetooth",true);

		    SSL ssl=new SSL(applicationId + deviceId);
		    if (ssl!=null) {
        		String licenseAsString=ssl.obfuscate(json,"license");

        		Json jsonOutput=Json.object();
        		jsonOutput.set("userid",userId);
        		jsonOutput.set("deviceid",deviceId);
        		jsonOutput.set("timestamp",nowAsISO);
        		jsonOutput.set("issuer",issuer);
        		jsonOutput.set("expires",expiresAsISO);
        		jsonOutput.set("license",licenseAsString+"=="+userId);
        		System.out.println(jsonOutput.toString());
		}

	}
}
