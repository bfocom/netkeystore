package com.bfo.netkeystore;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.concurrent.atomic.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.security.*;
import java.nio.*;
import java.io.*;
import com.bfo.json.*;
import com.bfo.zeroconf.*;
import com.sun.net.httpserver.*;

import java.util.prefs.Preferences;
import java.util.function.Consumer;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.event.*;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.Robot;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import javax.imageio.ImageIO;

class Server {

    private final boolean debug;
    private final Engine engine;
    private final Json config, shares;
    private HttpServer htserver;
    private Map<String,KeyStoreHolder> keystores;

    Server(Engine engine, Json config) throws IOException, GeneralSecurityException {
        this.engine = engine;
        this.config = config;
        this.shares = config.get("shares");
        debug = config.booleanValue("debug");
        this.keystores = new LinkedHashMap<String,KeyStoreHolder>();
        // These have to be loaded once because even if we call AuthProvider.logout(), the
        // PKCS#11 Provider will run out of tokens. So open it once and cache it.
        for (Map.Entry<Object,Json> e : shares.mapValue().entrySet()) {
            String name = e.getKey().toString();
            Json ksconfig = e.getValue();
            KeyStore keystore = engine.loadLocalKeyStore(ksconfig);
            String password = ksconfig.stringValue("password");
            String netpassword = ksconfig.isString("net_password") ? ksconfig.stringValue("net_password") : password;
            keystores.put(name, new KeyStoreHolder(keystore, password, netpassword));
        }
    }

    boolean isStarted() {
        return htserver != null;
    }

    int start() throws IOException {
        int port = engine.getServerPort();
        String path = engine.getServerPath();
        SSLContext ssl = engine.getServerSSLContext();
        if (ssl == null) {
            htserver = HttpServer.create();
        } else {
            htserver = HttpsServer.create();
            ((HttpsServer)htserver).setHttpsConfigurator(new HttpsConfigurator(ssl) {
                public void configure (HttpsParameters params) {
                    SSLParameters sslp = new SSLParameters();
                    sslp.setNeedClientAuth(config.booleanValue("client_auth"));
                    params.setSSLParameters(sslp);
                }
            });
        }
        htserver.bind(new InetSocketAddress(port), 0);
        if (path == null || path.equals("") || path.equals("/")) {
            path = "/";
        } else {
            if (path.charAt(0) != '/') {
                path = "/" + path;
            }
            if (path.charAt(path.length() - 1) != '/') {
                path = path + "/";
            }
        }
        htserver.createContext(path + "list-v1", new ListHandler());
        htserver.createContext(path + "sign-v1", new SignHandler());
        htserver.start();
        port = htserver.getAddress().getPort();
        engine.announce(true, port);
        return port;
    }

    void stop() throws InterruptedException {
        if (htserver != null) {
            htserver.stop(0);
            engine.announce(false, 0);
            htserver = null;
        }
    }

    static KeyStore.PasswordProtection getPasswordProtection(final Json config, final KeyStore.ProtectionParameter prot) {
        // This passwordProtection converts any callback supplied to this method to a password protection,
        // and converts from the "net_password" to the "password" if they're both specified.
        final char[] localPassword = config.has("password") ? config.stringValue("password").toCharArray() : null;     // Password to access KeyStore
        final char[] networkPassword = config.has("net_password") ? config.stringValue("net_password").toCharArray() : null;  // Password to be entered on network
        final KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(null) {
            public char[] getPassword() {
                char[] userPassword;
                if (prot instanceof KeyStore.PasswordProtection) {
                    userPassword = ((KeyStore.PasswordProtection)prot).getPassword();
                } else if (prot instanceof KeyStore.CallbackHandlerProtection) {
                    PasswordCallback cb = new PasswordCallback("Password: ", true);
                    try {
                        ((KeyStore.CallbackHandlerProtection)prot).getCallbackHandler().handle(new Callback[] { cb });
                    } catch (IOException e) {
                    } catch (UnsupportedCallbackException e) {
                    }
                    userPassword = cb.getPassword();
                } else {
                    userPassword = null;
                }
                char[] ret;
                if (localPassword == null || networkPassword == null) {
                    ret = userPassword; // The simple case: no password in config file. Use what remote gave us
                } else if (Arrays.equals(networkPassword, userPassword)) {
                    ret = localPassword;      // Remote password correct, convert to local password
                } else {
                    ret = new char[0];      // invalid password
                }
                return ret;
            }
        };
        return passwordProtection;
    }

    //----------------------------------------------------------------------------
    // Comms
    //----------------------------------------------------------------------------

    private class ListHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            Json res = null;
            try {
                InputStream in = exchange.getRequestBody();
                Json req = Json.readCbor(in);
                in.close();
                if (debug) System.out.println("# RX /list-v1: " + req);
                String storePassword = null;
                if (req.isList("auth")) {
                    Json auth = req.get("auth");
                    for (int i=0;i<auth.size();i++) {
                        if ("password".equals(auth.get(i).stringValue("type"))) {
                            storePassword = auth.get(i).stringValue("password");
                            break;
                        }
                    }
                }
                final Json keys = Json.read("{}");
                final Json auth = Json.read("[]");
                for (Map.Entry<String,KeyStoreHolder> e : keystores.entrySet()) {
                    final String storeName = e.getKey().toString();
                    final KeyStoreHolder holder = e.getValue();
                    if (storePassword == null || !storePassword.equals(holder.netpassword)) {
                        Json j = Json.read("{}");
                        j.put("type", "password");
                        j.put("prompt", "Password for \"" + storeName + "\"");
                        j.put("message", storePassword == null ? "Unspecified password" : "Invalid password");
                        auth.put(auth.size(), j);
                    } else {
                        KeyStore keystore = holder.keystore;
                        for (Enumeration<String> e2 = keystore.aliases();e2.hasMoreElements();) {
                            String name = e2.nextElement();
                            if (keystore.entryInstanceOf(name, KeyStore.PrivateKeyEntry.class)) {
                                Certificate[] certs = keystore.getCertificateChain(name);
                                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                                    PublicKey key = ((X509Certificate)certs[0]).getPublicKey();
                                    JWK jwk = new JWK(key);
                                    Json j = Json.read("{}");
                                    for (String s : new String[] { "kty", "use", "key_ops", "alg", "kid", "n", "d", "e", "crv" }) {
                                        if (jwk.has(s)) {
                                            j.put(s, jwk.get(s));
                                        }
                                    }
                                    // Do certs separately, Because JWK Base64 encodes as strings
                                    for (Certificate c : certs) {
                                        if (c instanceof X509Certificate) {
                                            Json l = j.get("x5c");
                                            if (l == null) {
                                                j.put("x5c", l = Json.read("[]"));
                                            }
                                            l.put(l.size(), ((X509Certificate)c).getEncoded());
                                        }
                                    }
                                    String fullName = storeName + "." + name;
                                    if (config.isMap("aliases")) {
                                        if (config.get("aliases").isString(fullName)) {
                                            String alias = config.get("aliases").stringValue(fullName);
                                            j.put("alias", alias);
                                        }
                                    }
                                    keys.put(fullName, j);
                                }
                            }
                        }
                    }
                }
                res = Json.read("{}");
                if (auth.size() > 0 && keys.size() == 0) {
                    res.put("type", "auth");
                    res.put("auth", auth);
                } else {
                    res.put("type", "list-v1");
                    res.put("keys", keys);
                    if (auth.size() > 0) {
                        res.put("auth", auth);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                res = Json.read("{}");
                res.put("type", "error");
                res.put("message", e.getMessage());
                StringWriter sb = new StringWriter();
                e.printStackTrace(new PrintWriter(sb, true));
                res.put("trace", sb.toString());
            } finally {
                if (debug) System.out.println("# TX /list-v1: " + res);
                byte[] cbor = res.toCbor().array();
                exchange.getResponseHeaders().set("Content-Type", "application/cbor");
                exchange.sendResponseHeaders(200, cbor.length);
                exchange.getResponseBody().write(cbor);
                exchange.getResponseBody().close();
            }
        }
    }

    private class SignHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            Json res = null;
            try {
                // input format is { "key": name, "digest": digest, "digest_alg": alg, "password": optional }
                // output format is { "signature": bytes }
                InputStream in = exchange.getRequestBody();
                Json req = Json.readCbor(in);
                if (debug) System.out.println("# RX /sign-v1: " + req);
                in.close();
                String keyname = req.stringValue("key");
                ByteBuffer buffer = req.bufferValue("digest");
                String err = null;
                Json auth = null;
                if (keyname == null) {
                    err = "no \"key\" specified";
                } else if (buffer == null) {
                    err = "no \"digest\" specified";
                } else {
                    err = "key \"" + keyname + "\" not found";
                    for (Map.Entry<String,KeyStoreHolder> e : keystores.entrySet()) {
                        final String storeName = e.getKey().toString();
                        final KeyStoreHolder holder = e.getValue();
                        final KeyStore keystore = holder.keystore;
                        if (keyname.startsWith(storeName + ".")) {
                            err = "Key \"" + keyname + "\" not found in store";
                            keyname = keyname.substring(storeName.length() + 1);
                            String storePassword = null, keyPassword = null;
                            if (req.isList("auth")) {
                                auth = req.get("auth");
                                for (int pass=0;pass<2;pass++) {
                                    for (int i=0;i<auth.size();i++) {
                                        Json j = auth.get(i);
                                        if ("password".equals(j.stringValue("type")) && j.isString("password")) {
                                            if (pass == 0) {
                                                if (storeName.equals(j.stringValue("for"))) {
                                                    storePassword = j.stringValue("password");
                                                } else if (keyname.equals(j.stringValue("for"))) {
                                                    keyPassword = j.stringValue("password");
                                                }
                                            } else if (!j.isString("for")) {
                                                if (storePassword == null) {
                                                    storePassword = j.stringValue("password");
                                                } else if (keyPassword == null) {
                                                    keyPassword = j.stringValue("password");
                                                }
                                            }
                                        }
                                    }
                                }
                                if (keyPassword == null) {
                                    keyPassword = storePassword;
                                }
                                auth = null;
                            }
                            if (storePassword == null || !storePassword.equals(holder.netpassword)) {
                                auth = Json.read("[]");
                                Json j = Json.read("{}");
                                j.put("type", "password");
                                j.put("prompt", "Password for \"" + storeName + "\"");
                                j.put("message", storePassword == null ? "Unspecified password" : "Invalid password");
                                auth.put(0, j);
                                err = "auth";
                            } else {
                                KeyStore.Entry entry = null;
                                try {
                                    if (keyPassword.equals(holder.netpassword)) {
                                        keyPassword = holder.password;
                                    }
                                    entry = keystore.getEntry(keyname, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
                                } catch (UnrecoverableKeyException ex) {
                                    err = "auth";
                                    auth = Json.read("[]");
                                    Json j = Json.read("{}");
                                    j.put("type", "password");
                                    j.put("prompt", "Password for \"" + req.stringValue("key") + "\"");
                                    j.put("message", ex.getMessage());
                                    auth.put(0, j);
                                }
                                if (entry instanceof KeyStore.PrivateKeyEntry) {
                                    PrivateKey key = ((KeyStore.PrivateKeyEntry)entry).getPrivateKey();
                                    String keyalg = key.getAlgorithm();
                                    String sigalg;
                                    if (keyalg.equals("EC")) {
                                        keyalg = "ECDSA";
                                    }
                                    sigalg = "NONEwith" + keyalg;
                                    // spec not applicable with normal RSA or EC sigs, but process is in place.
                                    Class<? extends AlgorithmParameterSpec> algorithmParameterSpecClass = null;
                                    if ("NONEwithECDSA".equals(sigalg)) {
                                        algorithmParameterSpecClass = null;
                                    } else if ("NONEwithRSA".equals(sigalg)) {
                                        algorithmParameterSpecClass = null;
                                    }
                                    Signature sig = null;
                                    Provider provider = keystore.getProvider();
                                    try {
                                        sig = Signature.getInstance(sigalg, provider);
                                    } catch (NoSuchAlgorithmException ex) {
                                        provider = null;
                                        sig = Signature.getInstance(sigalg);
                                    }
                                    if (req.isBuffer("params") && algorithmParameterSpecClass != null) {
                                        AlgorithmParameters ap = provider == null ? AlgorithmParameters.getInstance(sigalg) : AlgorithmParameters.getInstance(sigalg, provider);
                                        ap.init(req.bufferValue("params").array());
                                        AlgorithmParameterSpec spec = ap.getParameterSpec(algorithmParameterSpecClass);
                                        sig.setParameter(spec);
                                    }
                                    sig.initSign(key);
                                    // RSASSA-PKCS1-v1_5 padding
                                    // https://datatracker.ietf.org/doc/html/rfc8017#page-47
                                    // https://stackoverflow.com/questions/69750026/create-sha256withrsa-in-two-steps
                                    String digestalg = req.stringValue("digest_alg");
                                    if (keyalg.equals("RSA")) {
                                        if ("sha1".equalsIgnoreCase(digestalg)) {
                                            sig.update(new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 });
                                        } else if ("sha256".equalsIgnoreCase(digestalg)) {
                                            sig.update(new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 });
                                        } else if ("sha384".equalsIgnoreCase(digestalg)) {
                                            sig.update(new byte[] { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00 });
                                        } else if ("sha512".equalsIgnoreCase(digestalg)) {
                                            sig.update(new byte[] { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 });
                                        } else {
                                            err = "Digest Algorithm \"" + digestalg + "\" not supported";
                                            digestalg = null;
                                        }
                                    }
                                    if (digestalg != null) {
                                        sig.update(buffer.array());
                                        byte[] sigbytes = sig.sign();
                                        keyalg = key.getAlgorithm();
                                        res = Json.read("{}");
                                        res.put("type", "sign-v1");
                                        res.put("signature", sigbytes);
                                        err = null;
                                        break;
                                    }
                                } else if (entry != null) {
                                    err = "Key \"" + keyname + "\" not a private key";
                                }
                            }
                        }
                    }
                }
                if (auth != null) {
                    res = Json.read("{}");
                    res.put("type", "auth");
                    res.put("auth", auth);
                } else if (err != null) {
                    res = Json.read("{}");
                    res.put("type", "error");
                    res.put("message", err);
                }
            } catch (Exception e) {
                e.printStackTrace();
                res = Json.read("{}");
                res.put("type", "error");
                res.put("message", e.getMessage());
                StringWriter sb = new StringWriter();
                e.printStackTrace(new PrintWriter(sb, true));
                res.put("trace", sb.toString());
            } finally {
                if (debug) System.out.println("# TX /sign-v1: " + res);
                byte[] cbor = res.toCbor().array();
                exchange.getResponseHeaders().set("Content-Type", "application/cbor");
                exchange.sendResponseHeaders(200, cbor.length);
                exchange.getResponseBody().write(cbor);
                exchange.getResponseBody().close();
            }
        }
    }

    private static class KeyStoreHolder {
        final KeyStore keystore;
        final String password, netpassword;
        KeyStoreHolder(KeyStore keystore, String password, String netpassword) {
            this.keystore = keystore;
            this.password = password;
            this.netpassword = netpassword;
        }
    }

    //----------------------------------------------------------------------------

    private static void help() {
        final String jar = "java -jar netkeystore-" + Server.class.getPackage().getImplementationVersion();
        System.out.println("Usage: " + jar + " --config <conf.yaml>  (for CLI use)");
        System.out.println("Usage: " + jar + "                       (for GUI use)");
        System.out.println("       " + jar + " --scan                (to scan for servers)");
        System.out.println("For details see https://github.com/faceless2/netkeystore");
        System.exit(0);
    }

    private static void guilog(Throwable e) {
        e.printStackTrace();
        StringWriter w = new StringWriter();
        e.printStackTrace(new PrintWriter(w));
        JOptionPane.showMessageDialog(null, w.toString(), "Error", JOptionPane.ERROR_MESSAGE);
    }

    private static void gui(final Engine engine, String userConfigFile) throws Exception {
        final Preferences prefs = Preferences.userNodeForPackage(Engine.class);
        final String configFile = userConfigFile != null ? userConfigFile : prefs.get("config", null);

        if (SystemTray.isSupported()) {
            final PopupMenu popup = new PopupMenu();
            final MenuItem about = new MenuItem("NetKeyStore " +  Server.class.getPackage().getImplementationVersion());
            final MenuItem confdetail = new MenuItem("Configuration: none");
            final MenuItem listening = new MenuItem("Not listening");
            final MenuItem conf = new MenuItem("Configure...");
            final MenuItem stop = new MenuItem("Start server");
            final MenuItem quit = new MenuItem("Quit");
            about.setEnabled(false);
            confdetail.setEnabled(false);
            listening.setEnabled(false);
            stop.setEnabled(false);

            popup.add(about);
            popup.add(confdetail);
            popup.add(listening);
            popup.addSeparator();
            popup.add(conf);
            popup.add(stop);
            popup.add(quit);

            final Consumer<File> loader = new Consumer<File>() {
                public void accept(File file) {
                    if (file != null && file.canRead()) {
                        try {
                            if (engine.getServer() != null && engine.getServer().isStarted()) {
                                engine.getServer().stop();
                                stop.setLabel("Start server");
                                stop.setEnabled(false);
                                Thread.sleep(100);
                            }
                            FileInputStream in = new FileInputStream(file);
                            confdetail.setLabel("Configuration: none");
                            listening.setLabel("Not listening");
                            engine.load(in);
                            in.close();
                            engine.getServer().start();
                            stop.setEnabled(true);
                            stop.setLabel("Stop server");
                            confdetail.setLabel("Configuration: " + file);
                            listening.setLabel("Listening on " + engine.getServerPort());
                            prefs.put("config", file.getPath());
                        } catch (Exception ex) {
                            guilog(ex);
                            prefs.remove("config");
                        }
                    }
                }
            };

            stop.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        if (engine.getServer() != null && engine.getServer().isStarted()) {
                            engine.getServer().stop();
                            listening.setLabel("Not listening");
                            stop.setLabel("Start server");
                        } else {
                            engine.getServer().start();
                            stop.setLabel("Stop server");
                            listening.setLabel("Listening on " + engine.getServerPort());
                        }
                    } catch (Exception ex) {
                        guilog(ex);
                    }
                }
            });

            conf.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        JFileChooser chooser = new JFileChooser(new File(System.getProperty("user.home")));
                        if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                            loader.accept(chooser.getSelectedFile());
                        }
                    } catch (Exception ex) {
                        guilog(ex);
                    }
                }
            });

            quit.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        if (engine.getServer() != null && engine.getServer().isStarted()) {
                            engine.getServer().stop();
                            Thread.sleep(100);
                        }
                    } catch (Exception ex) {}
                    System.exit(0);
                }
            });

            final TrayIcon trayIcon = new TrayIcon(ImageIO.read(Server.class.getResource("data/trayicon.png")), "BFO Publisher");
            final Robot robot = new Robot();
            trayIcon.setImageAutoSize(true);
            trayIcon.setPopupMenu(popup);
            trayIcon.setToolTip("NetKeyStore");
            SystemTray.getSystemTray().add(trayIcon);
            // Next bit makes things better on Windows
            trayIcon.addMouseListener(new MouseAdapter() {
                public void mouseClicked(MouseEvent e) {
                    // Turn left-click into right-click
                    if (e.getButton() == MouseEvent.BUTTON1) {
                        robot.mousePress(MouseEvent.BUTTON3_DOWN_MASK);
                        robot.mouseRelease(MouseEvent.BUTTON3_DOWN_MASK);
                    }
                }
            });

            if (configFile != null) {
                System.out.println("Loading \"" + configFile + "\"");
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        loader.accept(new File(configFile));
                    }
                });
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String config = null;
        Boolean gui = null;
        if (args.length == 0) {
            System.out.println("Starting with default arguments \"--gui\"");
            args = new String[] { "--gui" };
        }
        if (args.length == 1 && args[0].equals("--scan")) {
            Engine engine = new Engine();
            engine.debug = true;
            engine.startClient(true, true);
            while (true) {
                try {
                    synchronized(Server.class) {
                        Server.class.wait();
                    }
                } catch (InterruptedException e) { }
            }
        }
        for (int i=0;i<args.length;i++) {
            String s = args[i];
            if (s.equals("--config") && i+1 < args.length && config == null) {
                config = args[++i];
            } else if (s.equals("--gui") && gui == null) {
                gui = true;
            } else if (s.equals("--nogui") && gui == null) {
                gui = false;
            } else {
                System.err.println("Invalid argument \"" + args[i] + "\"");
                help();
            }
        }
        if (gui == null) {
            gui = false;
        }
        Engine engine = new Engine();
        if (gui) {
            gui(engine, config);
        } else {
            if (config == null) {
                help();
            }
            InputStream in = new FileInputStream(config);
            engine.load(in);
            in.close();
            engine.getServer().start();
            System.out.println("Listening on " + engine.getServerPort());
        }
    }

}
