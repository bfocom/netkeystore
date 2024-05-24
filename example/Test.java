import java.security.*;
import java.security.cert.X509Certificate;

public class Test {
    public static void main(String[] args) throws Exception {
        char[] password = "secret".toCharArray();
        String alias = "ks1.eckey";
        String alg = "SHA256withECDSA";

        Provider provider = new com.bfo.netkeystore.NetProvider();
        KeyStore keystore = KeyStore.getInstance("NetKeyStore", provider);
        keystore.load(null, password);

        PrivateKey privkey = (PrivateKey)keystore.getKey(alias, password);
        PublicKey pubkey = ((X509Certificate)keystore.getCertificate(alias)).getPublicKey();

        byte[] data = new byte[100];

        Signature sig = Signature.getInstance(alg, provider);
        sig.initSign(privkey);
        sig.update(data);
        byte[] sigbytes = sig.sign();

        sig.initVerify(pubkey);              // Verifying can be done, but will just
        sig.update(data);                    // proxy everything to a local signature.
        boolean verified = sig.verify(sigbytes);
        System.out.println("Verified: " + verified);
    }
}
