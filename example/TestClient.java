import java.util.*;
import java.io.*;
import java.security.*;
import javax.security.auth.callback.*;
import java.security.cert.X509Certificate;
import com.bfo.netkeystore.client.NetProvider;

/**
 * An example showing how to sign with the KeyStore
 *
 * There is very little here that is specific to NetKeyStore
 * other than creating the initial provider, and it's slightly
 * more complete than most Signature examples simply so it can
 * work with any key. If the alias, password and algorithm are
 * already known this could be reduced to a few lines.
 *
 * All parameters are optional; if run without any, it will find
 * any server announced on the network with Zeroconf and sign
 * some data with the first available key
 */
public class TestClient {

    public static void main(String[] args) throws Exception {
        String configFile = null;
        String alias = null;
        String storePassword = null;
        String keyPassword = null;
        String sigAlgorithm = null;
        for (int i=0;i<args.length;i++) {
            if (args[i].equals("--config") && i + 1 < args.length && configFile == null) {
                configFile = args[++i];
            } else if (args[i].equals("--alias") && i + 1 < args.length && alias == null) {
                alias = args[++i];
            } else if (args[i].equals("--key-password") && i + 1 < args.length && keyPassword == null) {
                keyPassword = args[++i];
            } else if (args[i].equals("--store-password") && i + 1 < args.length && storePassword == null) {
                storePassword = args[++i];
            } else if (args[i].equals("--algorithm") && i + 1 < args.length && sigAlgorithm == null) {
                sigAlgorithm = args[++i];
            } else {
                System.out.println("Usage: TestClient --config <configFile> --alias <alias>");
                System.out.println("                  --store-password <password> --key-password <password>");
                System.out.println("                  --algorithm <signature-algorithm>");
                System.out.println();
                System.out.println("All parameters are optional");
                System.out.println();
                System.exit(-1);
            }
        }

        // Create and configure the Provider
        Provider provider = new NetProvider();
        if (configFile != null) {
            FileInputStream in = new FileInputStream(configFile);
            provider.load(in);
            in.close();
        }
        KeyStore keystore = KeyStore.getInstance(NetProvider.KEYSTORE_TYPE, provider);

        // Below here there is nothing specific to NetKeyStore.
        // Use the passwords if specified, otherwise use a callback to prompt the user
        final KeyStore.ProtectionParameter storeProt;
        KeyStore.ProtectionParameter keyProt;
        CallbackHandler handler = new com.sun.security.auth.callback.TextCallbackHandler();

        // This little bit of code will open a Web Browser, if available, if authorization
        // is required for OAuth2 login. It's entirely optional and will be skipped if you're
        // running headless
        if (java.awt.Desktop.isDesktopSupported()) {
            final java.awt.Desktop desktop = java.awt.Desktop.getDesktop();
            if (desktop.isSupported(java.awt.Desktop.Action.APP_OPEN_URI)) {
                final CallbackHandler orig = handler;
                handler = new CallbackHandler() {
                    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                        for (Callback c : callbacks) {
                            if (c instanceof TextOutputCallback) {
                                try {
                                    String uri = ((TextOutputCallback)c).getMessage();
                                    desktop.browse(new java.net.URI(uri));
                                    return; // Will only ever be sent in a list of 1 item
                                } catch (java.net.URISyntaxException e) {}
                            }
                        }
                        orig.handle(callbacks);
                    }
                };
            }
        }

        if (storePassword != null) {
            storeProt = new KeyStore.PasswordProtection(storePassword.toCharArray());
        } else {
            storeProt = new KeyStore.CallbackHandlerProtection(handler);
        }
        if (keyPassword != null) {
            keyProt = new KeyStore.PasswordProtection(keyPassword.toCharArray());
        } else {
            keyProt = new KeyStore.CallbackHandlerProtection(handler);
        }

        // Load the KeyStore
        keystore.load(new KeyStore.LoadStoreParameter() {
            public KeyStore.ProtectionParameter	getProtectionParameter() {
                return storeProt;
            }
        });
        System.out.println("Available keys: ");
        for (Enumeration<String> e = keystore.aliases();e.hasMoreElements();) {
            String a = e.nextElement();
            if (alias == null) {
                alias = a;      // If none specified, choose the first available
            }
            System.out.println((alias.equals(a) ? "* " : "  ") + "\"" + a + "\"");
        }
        if (alias == null) {
            throw new IllegalStateException("No aliases found: are servers specified?");
        }
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(alias, keyProt);
        if (entry == null) {
            throw new IllegalStateException("Alias \"" + alias + "\" not found in " + Collections.list(keystore.aliases()));
        }
        PrivateKey privkey = entry.getPrivateKey();
        PublicKey pubkey = keystore.getCertificate(alias).getPublicKey();
        if (sigAlgorithm == null) {
            // Make guess at the signature algorithm based on the key. Typically  you know what
            // sort of key you have so this isn't necessary.
            if ("RSA".equals(pubkey.getAlgorithm())) {
                sigAlgorithm = "SHA256withRSA";
            } else if ("EC".equals(pubkey.getAlgorithm())) {
                String s = ((java.security.interfaces.ECKey)pubkey).getParams().toString();
                if (s.contains("secp384")) {    // Make wild assumptions about toString
                    sigAlgorithm = "SHA384withECDSA";
                } else if (s.contains("secp521")) {
                    sigAlgorithm = "SHA512withECDSA";
                } else {
                    sigAlgorithm = "SHA256withECDSA";
                }
            } else {
                throw new IllegalStateException("Unknown key type \"" + pubkey.getAlgorithm() + "\"");
            }
        }

        // Some data to sign.
        byte[] data = new byte[100];

        // Sign the data
        Signature sig = Signature.getInstance(sigAlgorithm, provider);
        sig.initSign(privkey);
        sig.update(data);
        byte[] sigbytes = sig.sign();

        // Verify the signature
        sig.initVerify(pubkey);                  // Verifying can be done too, but will just
        sig.update(data);                        // proxy everything to a local Provider.
        boolean verified = sig.verify(sigbytes);
        System.out.println("Verified: " + verified);
    }
}
