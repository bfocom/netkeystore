package com.bfo.netkeystore.client;

import java.util.*;
import java.util.prefs.*;
import java.util.concurrent.*;
import java.security.*;
import java.net.*;
import java.security.cert.*;
import javax.crypto.*;
import javax.security.auth.Subject;
import java.io.*;
import com.bfo.json.*;
import com.bfo.zeroconf.*;

class Core {

    private static final int ZEROCONFDELAY = 1000;      // How long to wait after Zeroconf starts before returning keys
    private static final String SERVICE = "_netkeystore._tcp";
    private static final String PREFNAME = "NetKeyStore-Authorizations";

    private final CertificateFactory certFactory;
    private final NetProvider provider;
    private final Map<String,Server> servers;
    private final Map<String,KeyStore.Entry> entries;
    private final Map<String,String> aliases;
    private boolean debug;
    private boolean connected;
    private String authFilename, authPassword, lang;
    private File base;
    private KeyStore authKeystore;
    private Json authorizations;
    private Zeroconf zeroconf;
    private ZeroconfListener zeroconfListener;
    private long initComplete;

    Core(NetProvider provider) {
        this.provider = provider;
        servers = new ConcurrentHashMap<String,Server>();
        entries = new ConcurrentHashMap<String,KeyStore.Entry>();
        aliases = new HashMap<String,String>();
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    void configure(Json config) throws Exception {
        if (config == null) {
            config = Json.read("{}");
            config.put("zeroconf", true);
        }
        debug = config.booleanValue("debug");
        lang = config.stringValue("lang");
        if (lang != null) {
            if ("none".equals(lang)) {
                lang = null;
            } else if ("system".equals(lang)) {
                lang = Locale.getDefault().toLanguageTag();
            } else {
                if (Locale.forLanguageTag(lang).toLanguageTag().equals("und")) {
                    lang = null;
                }
            }
        }
        if (config.has("base")) {
            File file = config.isString("base") ? new File(config.stringValue("base")) : null;
            if (file != null && file.isDirectory()) {
                this.base = file;
            } else if (file != null && file.exists()) {
                this.base = file.getParentFile();
            } else {
                throw new IllegalArgumentException("Invalid \"base\" property " + config.get("base") + ": file not found");
            }
        }
        if (config.isMap("authorizations")) {
            authFilename = config.get("authorizations").stringValue("keystore");
            authPassword = config.get("authorizations").stringValue("password");
        }
        loadAuthorization();
        if (config.isMap("aliases")) {
            for (Map.Entry<Object,Json> e : config.get("aliases").mapValue().entrySet()) {
                if (e.getKey() instanceof String && e.getValue().isString()) {
                    aliases.put((String)e.getKey(), e.getValue().stringValue());
                }
            }
        }
        if (config.isMap("servers")) {
            for (Map.Entry<Object,Json> e : config.get("servers").mapValue().entrySet()) {
                final String name = e.getKey().toString();
                Json serverJson = e.getValue();
                if (!servers.containsKey(name) && !serverJson.booleanValue("disabled")) {
                    addServer(name, serverJson, false);
                }
            }
        }

        if (!config.isBoolean("zeroconf") || config.booleanValue("zeroconf")) {
            zeroconf = new Zeroconf();
            zeroconf.query(SERVICE, null);
            zeroconf.addListener(zeroconfListener = new ZeroconfListener() {
                @Override public void serviceNamed(String type, String name) {
                    if (type.equals(SERVICE)) {
                        zeroconf.query(type, name);
                    }
                }
                @Override public void serviceAnnounced(Service service) {
                    if (SERVICE.equals(service.getType()) && !service.getAddresses().isEmpty()) {
                        InetSocketAddress address = new InetSocketAddress(service.getAddresses().iterator().next(), service.getPort());
                        if ("2".equals(service.getText().get("version"))) {
                            try {
                                String name = service.getName();
                                Json json = Json.read(service.getText().get("config"));
                                if (!servers.containsKey(name)) {
                                    addServer(name, json, true);
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
                @Override public void serviceExpired(Service service) {
                    if (SERVICE.equals(service.getType())) {
                        String name = service.getName();
                        removeServer(name, true);
                    }
                }
            });
            int delay = config.isNumber("zeroconf-wait") ? config.numberValue("zeroconf-wait").intValue() : ZEROCONFDELAY;
            if (delay < 0 || delay > 5000) {    // 5s is orders of magnitude more than will ever be required
                delay = ZEROCONFDELAY;
            }
            initComplete = Math.max(initComplete, System.currentTimeMillis() + delay);
        }
    }

    private void addServer(String name, Json json, boolean auto) throws Exception {
        String type = json.stringValue("type");
        json = Json.read(json.toString()); // clone
        if (authorizations.isMap(name)) {
            mergeJson(json, Json.read(authorizations.get(name).toString()));
        }
        Server server = null;
        if (type == null) {
            throw new IllegalArgumentException("Server \"" + name + "\" missing required \"type\" property");
        } else if ("csc".equals(type)) {
            server = new CSCServer(this);
        } else {
            throw new IllegalArgumentException("Server \"" + name + "\" invalid type \"" + type + "\"");
        }
        server.configure(name, json, auto);
        servers.put(name, server);
    }

    private void removeServer(String name, boolean auto) {
        Server server = servers.get(name);
        boolean remove = false;
        try {
            remove = server.shutdown(auto);
        } catch (Exception e) {
            remove = true;
        }
        if (remove) {
            servers.remove(name);
            for (Iterator<Map.Entry<String,KeyStore.Entry>> i=entries.entrySet().iterator();i.hasNext();) {
                Map.Entry<String,KeyStore.Entry> e = i.next();
                String keyname = e.getKey();
                KeyStore.Entry entry = e.getValue();
                if (entry instanceof KeyStore.PrivateKeyEntry && ((KeyStore.PrivateKeyEntry)entry).getPrivateKey() instanceof NetPrivateKey) {
                    NetPrivateKey key = (NetPrivateKey)((KeyStore.PrivateKeyEntry)entry).getPrivateKey();
                    if (key.getServer() == server) {
                        entries.remove(keyname);
                    }
                }
            }
        }
    }

    synchronized void waitUntilInitialized() {
        // If we are looking for Zeroconf servers, we need to wait for them to report
        long diff = initComplete - System.currentTimeMillis();
        if (diff > 0 && diff < Integer.MAX_VALUE) {     // Just in case
            try {
                Thread.sleep((int)diff);
            } catch (InterruptedException e) {}
        }
    }

    String getLang() {
        return lang;
    }

    File getBase() {
        return base;
    }

    boolean isDebug() {
        return debug;
    }

    void debug(String msg) {
        if (isDebug()) {
            System.out.println("DEBUG: " + msg);
        }
    }

    void warning(String msg) {
        try {
            System.getLogger("com.bfo.netkeystore.client").log(System.Logger.Level.WARNING, msg);   // If compiling under Java8, remove this line
            return;                                                                                 // If compiling under Java8, remove this line
        } catch (Throwable e) {}
        try {
            java.util.logging.Logger.getLogger("com.bfo.netkeystore.client").warning(msg);
        } catch (Throwable e2) {
            System.out.println("WARNING: " + msg);
        }
    }

    boolean isConnected() {
        return connected;
    }

    synchronized void login(Subject subject, KeyStore.ProtectionParameter prot) throws UnrecoverableKeyException, IOException {
        waitUntilInitialized();
        if (!connected) {
            connected = true;
            for (Server server : servers.values()) {
                server.login(subject, prot);
            }
        }
    }

    void logout() throws IOException {
        if (connected) {
            connected = false;
            for (Server server : servers.values()) {
                server.logout();
            }
        }
    }

    synchronized void load() throws IOException {
        waitUntilInitialized();
        if (!connected) {
            throw new IllegalStateException("Not connected");
        }
        for (Server server : servers.values()) {
            server.load();
        }
    }

    void addKey(String name, KeyStore.Entry entry) {
        entries.put(name, entry);
        for (Map.Entry<String,String> e : aliases.entrySet()) {
            if (e.getValue().equals(name)) {
                entries.put(e.getKey(), entry);
            }
        }
    }

    void addSignatureAlgorithm(SignatureAlgorithm algorithm) {
        provider.addSignatureAlgorithm(algorithm);
    }

    SignatureAlgorithm getSignatureAlgorithm(String name) {
        for (Server server : servers.values()) {
            SignatureAlgorithm alg = server.getSignatureAlgorithm(name);
            if (alg != null) {
                return alg;
            }
        }
        return null;
    }

    private void loadAuthorization() throws Exception {
        if (authFilename == null) {
            Preferences prefs = Preferences.userNodeForPackage(getClass());
            try {
                if (authPassword != null) {
                    byte[] buf = prefs.getByteArray(PREFNAME, null);
                    if (buf != null) {
                        authKeystore = loadKeyStore("preferences", authPassword);
                        if (authKeystore.isKeyEntry("authorizations")) {
                            SecretKey key = (SecretKey)authKeystore.getKey("authorizations", authPassword.toCharArray());
                            authorizations = Json.read(new ByteArrayInputStream(key.getEncoded()));
                        }
                    }
                } else {
                    authorizations = Json.read(prefs.get(PREFNAME, null));
                }
            } catch (Exception e) {
                // Fail or reset? Well, no file is given, it's a transient thing anyway and
                // the user has no ability to clear it. If they cared about permanence
                // they would have specified a file. So zero it.
                authKeystore = null;
                authorizations = null;
            }
        } else {
            File file = new File(base, authFilename);
            if (file.canRead()) {
                if (authPassword == null) {
                    FileInputStream in = new FileInputStream(file);
                    authorizations = Json.read(in);
                    in.close();
                } else {
                    authKeystore = loadKeyStore(authFilename, authPassword);
                    if (authKeystore.isKeyEntry("authorizations")) {
                        SecretKey key = (SecretKey)authKeystore.getKey("authorizations", authPassword.toCharArray());
                        authorizations = Json.read(new ByteArrayInputStream(key.getEncoded()));
                    }
                }
            }
        }
        if (authorizations == null) {
            if (authPassword != null) {
                if (authFilename == null || authFilename.endsWith(".jks")) {
                    authKeystore = KeyStore.getInstance("JKS");
                } else if (authFilename.endsWith(".jceks")) {
                    authKeystore = KeyStore.getInstance("JCEKS");
                } else {
                    authKeystore = KeyStore.getInstance("PKCS12");
                }
                authKeystore.load(null, null);
            }
            authorizations = Json.read("{}");
        }
    }

    private void saveAuthorization() throws Exception {
        if (authFilename == null) {
            Preferences prefs = Preferences.userNodeForPackage(getClass());
            if (authKeystore != null) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                authKeystore.store(out, authPassword.toCharArray());
                out.close();
                prefs.putByteArray(PREFNAME, out.toByteArray());
            } else {
                prefs.put(PREFNAME, authorizations.toString());
            }
        } else {
            File file = new File(base, authFilename);
            File tmp = new File(file.getName() + ".tmp");
            FileOutputStream out = new FileOutputStream(tmp);
            if (authKeystore != null) {
                authKeystore.store(out, authPassword.toCharArray());
            } else {
                out.write(authorizations.toString().getBytes("UTF-8"));
            }
            out.close();
            tmp.renameTo(file);
        }
    }

    Json getAuthorization(String name) {
        return authorizations.get(name);
    }

    void setAuthorization(String name, Json json) {
        authorizations.put(name, json);
        try {
            saveAuthorization();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    Map<String,KeyStore.Entry> getEntries() {
        return entries;
    }

    Map<String,Server> getServers() {
        return Collections.<String,Server>unmodifiableMap(servers);
    }

    //----------------------------------------------------------------------------------------

    KeyStore loadKeyStore(String path, String password) throws Exception {
        File file = new File(base, path);
        if (file.canRead()) {
            try {
                BufferedInputStream in = new BufferedInputStream(new FileInputStream(file));
                byte[] buf = new byte[10];
                in.mark(buf.length);
                for (int i=0;i<buf.length;i++) {
                    buf[i] = (byte)in.read();
                }
                in.reset();
                String s = new String(buf, "ISO-8859-1");
                String type;
                if (s.startsWith("\u00fe\u00ed\u00fe\u00ed")) {
                    type = "JKS";
                } else if (s.startsWith("\u00ce\u00ce\u00ce\u00ce")) {
                    type = "JCEKS";
                } else {
                    type = "PKCS12";
                }
                KeyStore keystore = KeyStore.getInstance(type);
                keystore.load(in, password == null ? null : password.toCharArray());
                in.close();
                return keystore;
            } catch (Exception e) {
                throw (IOException)new IOException("Failed reading KeyStore from \"" + path + "\"").initCause(e);
            }
        } else {
            throw (IOException)new IOException("Failed reading KeyStore from \"" + path + "\": file not found");
        }
    }

    static void mergeJson(Json tgt, Json src) {
        for (Map.Entry<Object,Json> e : src.mapValue().entrySet()) {
            Object key = e.getKey();
            if (e.getValue().isMap() && tgt.isMap(key)) {
                mergeJson(tgt.get(key), e.getValue());
            } else {
                tgt.put(key, e.getValue());
            }
        }
    }


    X509Certificate decodeCertificate(String s) {
        try {
            s = s.replace("-","+").replace("_","/");      // just in case, convert from url-format
            byte[] data = Base64.getDecoder().decode(s);
            return (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(data));
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    String encodeCertificate(X509Certificate cert) throws Exception {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }


}
