package com.bfo.netkeystore.server;

import java.util.*;
import java.time.*;
import java.time.format.*;
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
import javax.crypto.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.io.*;
import com.bfo.json.*;
import com.bfo.zeroconf.*;
import com.sun.net.httpserver.*;

// For the GUI
import java.util.prefs.Preferences;
import java.util.function.Consumer;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.event.*;
import java.awt.FileDialog;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.Robot;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import javax.imageio.ImageIO;

public class Server {

    public static final String SERVICE = "_netkeystore._tcp";

    private static final int MAXRXBUF = 8192;   // we are never going to receive a POST with more data than this that's valid

    private boolean debug;
    private int maxrxbuf, version, usedport;
    private byte[] secret;
    private String url;
    private Random random;
    private Json config;
    private File base;
    private HttpServer htserver;
    private CallbackHandler callbackHandler;
    private CredentialCollection credentials;
    private final Map<String,SAD> sads;
    private final DateTimeFormatter dateFormatter;
    private String staticPath;
    private Authorization auth;
    private KeyAuthorization keyauth;
    private Zeroconf zeroconf;
    private Service zeroconfService;

    public Server() {
        this.sads = new HashMap<String,SAD>();
        this.random = new SecureRandom();
        dateFormatter = DateTimeFormatter.ofPattern("uuuuMMddHHmmss'Z'");
    }

    protected void debug(String s) {
        if (debug) {
            System.out.println("DEBUG: " + s);
        }
    }

    /**
     * Return the Authorization in use by this server, which will never be null
     */
    public Authorization getAuthorization() {
        return auth;
    }

    /**
     * Return the KeyAuthorization in use by this server, which may be null
     */
    public KeyAuthorization getKeyAuthorization() {
        return keyauth;
    }

    /**
     * Return the KeyAuthorization in use by this server, which may be null
     */
    public CredentialCollection getCredentials() {
        return credentials;
    }

    /**
    /**
     * Return the Random used by the Server
     */
    public Random getRandom() {
        return random;
    }

    /**
     * Return some secret bytes that apply only to this Server
     */
    public byte[] getSecret() {
        return secret;
    }

    /**
     * Return the name of the server, as set in the configuration
     */
    public String getName() {
        return config.stringValue("name");
    }

    /**
     * Return the URL the Webserver thinks it's listening on when running
     */
    public String getURL() {
        return url;
    }

    /**
     * Return the port the Webserver is listening on, or 0 if not started
     */
    public int getPort() {
        return usedport;
    }

    /**
     * Set the CallbackHandler to use for passwords, or null to retrieve them from the config file
     * @param handler the handler
     */
    public void setCallbackHandler(CallbackHandler handler) {
        this.callbackHandler = handler;
    }

    /**
     * Return true if the Webserver is started
     */
    public boolean isStarted() {
        return htserver != null;
    }

    boolean isDebug() {
        return debug;
    }

    /**
     * Configure the Server
     * @param in an InputStream containing a YAML configuration. The stream is not closed
     * @param base the optional File against which any relative paths in the configuration are resolved against. Normally the absolute path of the configuration file.
     * @throws Exception if the configuration is invalid for any reason
     */
    public void configure(InputStream in, File base) throws Exception {
        configure(Json.read(new YamlReader().setInput(in)), base);
    }

    /**
     * Configure the Server
     * @param config a configuration object
     * @param base the optional File against which any relative paths in the configuration are resolved against. Normally the absolute path of the configuration file.
     * @throws Exception if the configuration is invalid for any reason
     */
    public void configure(Json config, File base) throws Exception {
        if (isStarted()) {
            throw new IllegalStateException("Already started");
        }
        // Reset everything 
        debug = false;
        maxrxbuf = MAXRXBUF;
        version = 0;
        url = staticPath = null;
        htserver = null;
        sads.clear();
        auth = null;

        this.config = config;
        if (base != null && !base.isDirectory() && base.getParent() != null) {
            base = base.getParentFile();
        }
        if (config.has("base")) {
            File file = config.stringValue("base") != null ? new File(config.stringValue("base")) : null;
            if (file != null && file.isDirectory()) {
                base = file;
            } else if (file != null && file.exists()) {
                base = file.getParentFile();
            } else {
                throw new IllegalArgumentException("Invalid \"base\" property " + config.get("base") + ": file not found");
            }
        }

        this.base = base;
        this.version = config.isNumber("version") ? config.numberValue("version").intValue() : 1;
        if (version < 0 || version > 9) {
            this.version = 1;
        }
        this.debug = config.booleanValue("debug");
        if (config.isString("secret")) {
            secret = config.stringValue("secret").getBytes(StandardCharsets.ISO_8859_1);
        } else {
            secret = new byte[32];
            getRandom().nextBytes(secret);
        }
        if (config.isNumber("max_input_size")) {
            maxrxbuf = config.numberValue("max_input_size").intValue();
            if (maxrxbuf < 0 || maxrxbuf > 1024*1024) {
                maxrxbuf = MAXRXBUF;
            }
        }
        if (config.isString("url")) {
            this.url = config.stringValue("url");
        }
        if (config.isString("static")) {
            this.staticPath = config.stringValue("static");
            if (staticPath.endsWith("/")) {
                staticPath = staticPath.substring(0, staticPath.length() - 1);
            }
        }

        reload();

        if (!config.isMap("auth")) {
            throw new IllegalArgumentException("\"auth\" section missing");
        } else {
            Json authmap = config.get("auth");
            if (!authmap.isString("type")) {
                throw new IllegalArgumentException("\"auth\" section missing \"type\" property");
            } else {
                String authType = authmap.stringValue("type");
                if (authType.equals("open")) {
                    auth = Authorization.OPEN;
                } else if (authType.equals("basic")) {
                    auth = new BasicAuthorization();
              } else if (authType.equals("oauth2")) {
                    auth = new OAuth2Authorization();
                } else if (authType.equals("ssl")) {
//                    auth = new ClientCertificateAuthorization();    // TODO, with the X.500 identity from the client serving as the Principal
                } else {
                    try {
                        auth = (Authorization)Class.forName(authType).getDeclaredConstructor().newInstance();
                    } catch (Exception e) {
                        throw (RuntimeException)new IllegalArgumentException("\"auth\" section invalid \"type\" property \"" + authType + "\"").initCause(e);
                    }
                }
                auth.setServer(this);
                auth.configure(authmap);
            }
        }
        if (config.isMap("key_auth")) {
            Json authmap = config.get("key_auth");
            if (!authmap.isString("type")) {
                throw new IllegalArgumentException("\"auth\" section missing \"type\" property");
            } else {
                String authType = authmap.stringValue("type");
                if (authType.equals("explicit")) {
                    keyauth = KeyAuthorization.EXPLICIT;
                } else if (authType.equals("implicit")) {
                    keyauth = KeyAuthorization.IMPLICIT;
                } else {
                    try {
                        keyauth = (KeyAuthorization)Class.forName(authType).getDeclaredConstructor().newInstance();
                    } catch (Exception e) {
                        throw (RuntimeException)new IllegalArgumentException("\"keyauth\" section invalid \"type\" property \"" + authType + "\"").initCause(e);
                    }
                }
                keyauth.setServer(this);
                keyauth.configure(authmap);
            }
        } else {
            keyauth = KeyAuthorization.EXPLICIT;
        }
    }

    /**
     * Reload any KeyStores
     * @throws Exception if the keystore won't load
     */
    public void reload() throws Exception {
        credentials = new CredentialCollection(this);
        credentials.configure(config);
    }

    /**
     * Start the webserver
     * @throws Exception if the server won't start
     */
    public void start() throws Exception {
        if (isStarted()) {
            throw new IllegalStateException("Already started");
        }
        int port = config.isNumber("port") ? config.numberValue("port").intValue() : 0;
        if (port < 1 || port > 65535) {
            port = 0;
        }
        String prefix = config.stringValue("prefix");
        SSLContext sslcontext = null;
        if (config.isMap("https")) {
            Json ssljson = config.get("https");
            char[] password = ssljson.isString("password") ? ssljson.stringValue("password").toCharArray() : null;
            if (password == null) {
                if (callbackHandler != null) {
                    PasswordCallback callback = new PasswordCallback("SSL Keystore Password: ", false);
                    callbackHandler.handle(new Callback[] { callback });
                    password = callback.getPassword();
                }
                if (password == null) {
                    throw new IOException("SSL Password required");
                }
                ssljson = Json.read(ssljson.toString());
                ssljson.put("password", new String(password));
            }
            KeyStore keystore = loadKeyStore("ssl", ssljson);
            sslcontext = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keystore, password);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keystore);
            sslcontext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        }

        if (sslcontext == null) {
            htserver = HttpServer.create();
        } else {
            htserver = HttpsServer.create();
            ((HttpsServer)htserver).setHttpsConfigurator(new HttpsConfigurator(sslcontext) {
                public void configure (HttpsParameters params) {
                    SSLParameters sslp = new SSLParameters();
                    params.setSSLParameters(sslp);
                }
            });
        }
        htserver.bind(new InetSocketAddress(port), 0);
        if (prefix == null || prefix.equals("") || prefix.equals("/")) {
            prefix = "/";
        } else {
            if (prefix.charAt(0) != '/') {
                prefix = "/" + prefix;
            }
            if (prefix.charAt(prefix.length() - 1) != '/') {
                prefix = prefix + "/";
            }
        }
        prefix += "csc/v" + version + "/";
        final Json info = Json.read(config.isMap("info") ? config.get("info").toString() : "{}");
        for (String s : new String[] { "name", "lang", "version" }) {
            if (config.isString(s)) {
                info.put(s, config.stringValue(s));
            }
        }
        info.put("methods", Json.read("[]"));
        info.get("methods").put(info.get("methods").size(), "info");
        info.get("methods").put(info.get("methods").size(), "credentials/list");
        info.get("methods").put(info.get("methods").size(), "credentials/info");
        info.get("methods").put(info.get("methods").size(), "credentials/authorize");
        info.get("methods").put(info.get("methods").size(), "credentials/signHash");
        htserver.createContext(prefix + "info", new InfoHandler(info));
        htserver.createContext(prefix + "credentials/list", new CredentialsListHandler());
        htserver.createContext(prefix + "credentials/info", new CredentialsInfoHandler());
        htserver.createContext(prefix + "credentials/authorize", new CredentialsAuthorizeHandler());
        htserver.createContext(prefix + "signatures/signHash", new SignaturesSignHashHandler());
        htserver.createContext("/", new FallbackHandler());
        auth.initialize(htserver, prefix, info);
        keyauth.initialize(htserver, prefix, info);
        info.put("authType", new Json(new String[] { auth.type() }));
        htserver.start();
        port = htserver.getAddress().getPort();
        if (this.url == null) {
            String hostname = config.isString("hostname") ? config.stringValue("hostname") : null;
            if (hostname == null) {
                hostname = InetAddress.getLocalHost().getHostName() + ".local";    // If we're using it anywhere it's zeroconf
            }
            this.url = (sslcontext == null ? "http://" : "https://") +  hostname + ":" + port + prefix;
        }
        if (auth.type().startsWith("oauth2") && !info.isString("oauth") && !info.isString("oauth2Issuer")) {
            info.put("oauth2", getURL());
        }

        if (config.isMap("zeronf") || (config.isBoolean("zeroconf") && config.booleanValue("zeroconf"))) {
            zeroconf = new Zeroconf();
            Json j;
            if (config.isMap("zeroconf")) {
                j = Json.read(config.get("zeroconf").toString());
            } else {
                j = Json.read("{}");
            }
            if (!j.isString("name")) {
                j.put("name", config.stringValue("name"));
            }
            if (!j.isString("type")) {
                j.put("type", "csc");
            }
            if (!j.isString("url")) {
                j.put("url", getURL());
            }
            String name = j.stringValue("name");
            if (name != null) {
                zeroconfService = new Service.Builder().setName(name).setType(SERVICE).setPort(port).put("version", "2").put("config", j.toString()).build(zeroconf);
                zeroconfService.announce();
            }
        }
        usedport = port;
    }

    /**
     * Stop the webserver
     * @throws InterruptedException if the server was interruped while stopping
     */
    public void stop() throws InterruptedException {
        if (!isStarted()) {
            throw new IllegalStateException("Already stopped");
        }
        if (zeroconfService != null) {
            zeroconfService.cancel();
            zeroconfService = null;
        }
        htserver.stop(0);
        htserver = null;
        usedport = 0;
    }

    //----------------------------------------------------------------------------
    // Comms
    //----------------------------------------------------------------------------

    Json receive(HttpExchange exchange) throws IOException {
        InputStream in = null;
        try {
            in = exchange.getRequestBody();
            // We should never receive more than N bytes
            byte[] buf = new byte[maxrxbuf];
            int len = 0, l;
            while (len < buf.length && (l=in.read(buf, len, buf.length - len)) >= 0) {
                len += l;
            }
            if (len == buf.length) {
                send(exchange, 413, createError("invalid_request", "Too much data received", null), null);
                return null;
            }
            try {
                Json json = Json.read(new ByteArrayInputStream(buf, 0, len));
                if (debug) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("# RX ");
                    sb.append(exchange.getRequestURI().getPath());
                    String auth = exchange.getRequestHeaders().getFirst("Authorization");
                    if (auth != null) {
//                        sb.append("[" + auth + "]");
                    }
                    sb.append(" → ");
                    sb.append(json);
                    debug(sb.toString());
                }
                return json;
            } catch (Exception e) {
                send(exchange, 400, createError("invalid_request", "Malformed JSON", e), null);
            }
        } finally {
            if (in != null) try { in.close(); } catch (Exception e) {}
        }
        return null;
    }

    void send(HttpExchange exchange, int code, Json json, Map<String,String> headers) throws IOException {
        String s = json != null ? json.toString() : null;
        if (debug) {
            StringBuilder sb = new StringBuilder();
            sb.append("# TX ");
            sb.append(exchange.getRequestURI().getPath());
            sb.append(" ← ");
            sb.append(s);
            debug(sb.toString());
        }
        if (headers != null) {
            for (Map.Entry<String,String> e : headers.entrySet()) {
                exchange.getResponseHeaders().set(e.getKey(), e.getValue());
            }
        }
        if (s == null) {
            exchange.sendResponseHeaders(code, -1);
        } else {
            exchange.getResponseHeaders().set("Content-Type", "application/json");      // UTF-8 is default and only valid charset
            byte[] data = s.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(code, data.length);
            exchange.getResponseBody().write(data);
            exchange.getResponseBody().close();
        }
    }

    static Json createError(String msg, String description, Throwable throwable) {
        Json j = Json.read("{}");
        j.put("error", msg);
        if (description != null) {
            j.put("error_description", description);
        }
        if (throwable != null) {
            StringWriter sb = new StringWriter();
            throwable.printStackTrace(new PrintWriter(sb, true));
            j.put("trace", sb.toString());
        }
        return j;
    }

    private class InfoHandler implements HttpHandler {
        final Json info;
        InfoHandler(Json info) {
            this.info = info;
        }
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = receive(exchange);
                if (req != null) {
                    send(exchange, 200, info, null);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class CredentialsListHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = receive(exchange);
                if (req != null) {
                    Principal principal = auth.authorize(exchange);
                    if (principal != null) {
                        String userid = req.stringValue("userID");
                        Json res = Json.read("{}"); 
                        Json idlist = Json.read("[]"); 
                        res.put("credentialIDs", credentials.getCredentials(principal, userid));
                        send(exchange, 200, res, null);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class CredentialsInfoHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = receive(exchange);
                if (req != null) {
                    Principal principal = auth.authorize(exchange);
                    if (principal != null) {
                        if (!req.isString("credentialID")) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) string parameter credentialID", null), null);
                        } else {
                            final String cid = req.stringValue("credentialID");
                            final Credential credential = credentials.getCredential(principal, cid);
                            if (credential == null) {
                                send(exchange, 400, createError("invalid_request", "Invalid parameter credentialID", null), null);
                            } else {
                                Json res = Json.read("{}"); 
                                res.put("key", Json.read(credential.getInfo().toString()));
                                if (req.booleanValue("certInfo")) {
                                    List<X509Certificate> certs = credential.getCertificates();
                                    res.put("cert", Json.read("{}"));
                                    if (!"none".equals(req.stringValue("certificates"))) {
                                        String wc = req.stringValue("certificates");
                                        int len;
                                        if (wc == null || "single".equals(wc)) {
                                            len = 1;
                                        } else if ("chain".equals(wc)) {
                                            len = certs.size();
                                        } else {
                                            send(exchange, 400, createError("invalid_request", "Invalid parameter certificates", null), null);
                                            return;
                                        }
                                        Json certlist = Json.read("[]");
                                        res.get("cert").put("certificates", certlist);
                                        for (int i=0;i<len;i++) {
                                            certlist.put(certlist.size(), Base64.getEncoder().encodeToString(certs.get(i).getEncoded()));
                                        }
                                    }
                                    X509Certificate cert = certs.get(0);
                                    res.get("cert").put("issuerDN", cert.getIssuerX500Principal().getName());
                                    res.get("cert").put("subjectDN", cert.getSubjectX500Principal().getName());
                                    res.get("cert").put("serialNumber", cert.getSerialNumber().toString(16));
                                    res.get("cert").put("validFrom", dateFormatter.format(LocalDateTime.ofInstant(cert.getNotBefore().toInstant(), ZoneOffset.UTC)));
                                    res.get("cert").put("validTo", dateFormatter.format(LocalDateTime.ofInstant(cert.getNotAfter().toInstant(), ZoneOffset.UTC)));
                                }
                                res.put("SCAL", "1");
                                keyauth.setKeyInfo(principal, credential, cid, res);
                                send(exchange, 200, res, null);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class CredentialsAuthorizeHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = receive(exchange);
                if (req != null) {
                    Principal principal = auth.authorize(exchange);
                    if (principal != null) {
                        if (!req.isNumber("numSignatures") || req.get("numSignatures").toString().contains(".")) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) integer parameter numSignatures", null), null);
                        } else if (req.numberValue("numSignatures").intValue() != 1) {
                            send(exchange, 400, createError("invalid_request", "Numbers of signatures is not one", null), null);
                        } else if (!req.isString("credentialID")) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) string parameter credentialID", null), null);
                        } else {
                            final String cid = req.stringValue("credentialID");
                            final Credential credential = credentials.getCredential(principal, cid);
                            if (credential == null) {
                                send(exchange, 400, createError("invalid_request", "Invalid parameter credentialID", null), null);
                            } else {
                                PrivateKey key = keyauth.getPrivateKey(principal, credential, cid, req);
                                if (key != null) {
                                    byte[] uuid = new byte[32];
                                    random.nextBytes(uuid);
                                    String sadkey = Base64.getUrlEncoder().encodeToString(uuid);
                                    synchronized(sads) {
                                        for (Iterator<SAD> i = sads.values().iterator();i.hasNext();) {
                                            SAD sad = i.next();
                                            if (sad.isExpired()) {
                                                i.remove();
                                            }
                                        }
                                        sads.put(sadkey, new SAD(sadkey, credential, key));
                                    }
                                    Json res = Json.read("{}");
                                    res.put("SAD", sadkey);
                                    send(exchange, 200, res, null);
                                } else {
                                    send(exchange, 400, createError("invalid_pin", "The " + (keyauth.isOTP() ? "OTP" : "PIN") + " is invalid", null), null);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class SignaturesSignHashHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = receive(exchange);
                if (req != null) {
                    Principal principal = auth.authorize(exchange);
                    if (principal != null) {
                        if (!req.isString("SAD")) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) string parameter SAD", null), null);
                        } else if (!req.isString("credentialID")) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) string parameter credentialID", null), null);
                        } else if (!req.isString("signAlgo")) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) string parameter signAlgo", null), null);
                        } else if (!req.isList("hash") || req.get("hash").size() != 1 || !req.get("hash").isString(0)) {
                            send(exchange, 400, createError("invalid_request", "Missing (or invalid type) array parameter hash, or does not contain a single string", null), null);
                        } else {
                            final String cid = req.stringValue("credentialID");
                            final Credential credential = credentials.getCredential(principal, cid);
                            if (cid == null) {
                                send(exchange, 400, createError("invalid_request", "Invalid parameter credentialID", null), null);
                            } else {
                                String sadkey = req.stringValue("SAD");
                                SAD sad = null;
                                synchronized(sads) {
                                    for (Iterator<SAD> i = sads.values().iterator();i.hasNext();) {
                                        SAD tsad = i.next();
                                        if (tsad.isExpired()) {
                                            i.remove();
                                        } else if (tsad.id.equals(sadkey) && tsad.credential == credential) {
                                            sad = tsad;
                                        }
                                    }
                                }
                                if (sad == null) {
                                    send(exchange, 400, createError("invalid_request", "Invalid parameter SAD", null), null);
                                } else {
                                    byte[] hash = null;
                                    String signAlgoName = req.stringValue("signAlgo");
                                    for (int i=0;i<sad.credential.getInfo().get("algo").size();i++) {
                                        if (signAlgoName.equals(sad.credential.getInfo().get("algo").get(i).stringValue())) {
                                            try {
                                                hash = Base64.getDecoder().decode(req.get("hash").stringValue(0));
                                            } catch (Exception e) {
                                                signAlgoName = null;
                                                send(exchange, 400, createError("invalid_request", "Invalid Base64 hash string parameter", null), null);
                                            }
                                            break;
                                        }
                                    }
                                    if (hash == null && signAlgoName != null) {
                                        send(exchange, 400, createError("invalid_request", "Invalid parameter signAlgo", null), null);
                                    } else {
                                        // We're off!
                                        SignatureAlgorithm algo = SignatureAlgorithm.get(signAlgoName);
                                        String sigalg = algo.signingAlgorithmWithExternalDigest();
                                        Class<? extends AlgorithmParameterSpec> algorithmParameterSpecClass = algo.signingAlgorithmParameterClass();
                                        Signature sig = null;
                                        Provider provider = credential.getKeyStore().getProvider();
                                        try {
                                            sig = Signature.getInstance(sigalg, provider);
                                        } catch (NoSuchAlgorithmException ex) {
                                            provider = null;
                                            sig = Signature.getInstance(sigalg);
                                        }
                                        if (algorithmParameterSpecClass != null && req.isString("signAlgoParams")) {
                                            String signAlgoParamsString = req.stringValue("signAlgoParams");
                                            byte[] signAlgoParams = null;
                                            try {
                                                signAlgoParams = Base64.getDecoder().decode(signAlgoParamsString);
                                            } catch (Exception e) {
                                                send(exchange, 400, createError("invalid_request", "Invalid Base64 signAlgoParams string parameter", null), null);
                                                sig = null;
                                            }
                                            if (sig != null) {
                                                AlgorithmParameters ap = provider == null ? AlgorithmParameters.getInstance(sigalg) : AlgorithmParameters.getInstance(sigalg, provider);
                                                ap.init(signAlgoParams);
                                                AlgorithmParameterSpec spec = ap.getParameterSpec(algorithmParameterSpecClass);
                                                sig.setParameter(spec);
                                            }
                                        }
                                        if (sig != null) {
                                            sig.initSign(sad.key);
                                            algo.sign(hash, sig);
                                            byte[] sigbytes = sig.sign();
                                            Json res = Json.read("{}");
                                            res.put("signatures", Json.read("[]"));
                                            res.get("signatures").put(0, Base64.getEncoder().encodeToString(sigbytes));
                                            send(exchange, 200, res, null);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class FallbackHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            Principal principal = auth.authorize(exchange);
            if (principal != null) {    // Only server to authorized people
                int code = 500;
                byte[] data = null;
                if (staticPath != null) {
                    List<String> segments = new ArrayList<String>(Arrays.asList(exchange.getRequestURI().getPath().split("/")));;
                    for (int i=0;i<segments.size();i++) {
                        String p = segments.get(i);
                        if (p.equals("") || p.equals(".") || (p.equals("..") && i == 0)) {
                            segments.remove(i--);
                        } else if (p.equals("..")) {
                            segments.remove(--i);
                            segments.remove(i--);
                        }
                    }
                    Path path = Paths.get(staticPath + "/" + String.join("/", segments));
                    if (Files.isReadable(path) && Files.isRegularFile(path)) {
                        long size = Files.size(path);
                        if (size < 1024*1024) { // This is a convenient helper, not a proper webserver!
                            code = 200;
                            data = Files.readAllBytes(path);
                            String name = path.toString().toLowerCase();
                            String type = "application/octet-stream";
                            if (name.endsWith(".html") || name.endsWith(".htm")) {
                                type = "text/html";
                            } else if (name.endsWith(".css")) {
                                type = "text/css";
                            } else if (name.endsWith(".js")) {
                                type = "application/javascript";
                            } else if (name.endsWith(".png")) {
                                type = "image/png";
                            } else if (name.endsWith(".jpg") || name.endsWith(".jpeg")) {
                                type = "image/jpeg";
                            } else if (name.endsWith(".svg")) {
                                type = "image/svg+xml";
                            }
                            if (debug) {
                                StringBuilder sb = new StringBuilder();
                                sb.append("# TX ");
                                sb.append(exchange.getRequestURI().getPath());
                                sb.append(" ← ");
                                sb.append(path + " (" + data.length +" bytes)");
                                debug(sb.toString());
                            }
                            exchange.getResponseHeaders().set("Content-Type", type);
                        } else {
                            code = 403;
                            data = "File too large\n".getBytes(StandardCharsets.UTF_8);
                        }
                    }
                }
                if (data == null) {
                    code = 404;
                    data = "Not found\n".getBytes(StandardCharsets.UTF_8);
                }
                exchange.sendResponseHeaders(code, data.length);
                exchange.getResponseBody().write(data);
                exchange.getResponseBody().close();
            }
        }
    }

    //-----------------------------------------------
    // Helper stuff
    //-----------------------------------------------

    KeyStore loadKeyStore(String name, Json config) throws IOException, GeneralSecurityException {
        try {
            KeyStore.ProtectionParameter prot = null;
            if (config.isString("password")) {
                prot = new KeyStore.PasswordProtection(config.stringValue("password").toCharArray());
            } else if (callbackHandler != null) {
                prot = new KeyStore.CallbackHandlerProtection(callbackHandler);
            }
            String type = config.stringValue("type");
            String path = config.stringValue("path");
            String providerName = config.stringValue("provider");
            Provider provider = null;
            if ("pkcs11".equals(type)) {
                provider = Security.getProvider("SunPKCS11");
                StringBuilder sb = new StringBuilder();
                sb.append("--");
                if (!config.isString("name")) {
                    sb.append("name = " + name + "\n");
                }
                for (Map.Entry<Object,Json> e : config.mapValue().entrySet()) {
                    String key = e.getKey().toString();
                    switch (key.toLowerCase()) {
                        case "name":
                        case "library":
                        case "slotlistindex":
                        case "slot":
                        case "description":
                        case "enabledmechanisms":
                        case "disabedmechanisms":
                            sb.append(key + " = " + e.getValue().stringValue()+ "\n");
                            break;
                    }
                    // TODO attributes
                }
                provider = provider.configure(sb.toString());   // If compiling under Java8, uncomment next line instead
                // provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(sb.toString().getBytes("UTF-8")));
                path = null;
            } else {
                if (providerName != null) {
                    for (Provider p : Security.getProviders()) {
                        if (p.getClass().getName().equals(providerName) || p.getName().equals(providerName)) {
                            provider = p;
                            break;
                        }
                    }
                    if (provider == null) {
                        throw new IllegalArgumentException("Provider \"" + providerName+ "\" not found");
                    }
                }
            }

            final Provider fprovider = provider;
            if (provider instanceof AuthProvider) {
                CallbackHandler cbhandler = null;
                if (prot instanceof KeyStore.CallbackHandlerProtection) {
                    cbhandler = ((KeyStore.CallbackHandlerProtection)prot).getCallbackHandler();
                } else {
                    final char[] password = ((KeyStore.PasswordProtection)prot).getPassword();
                    cbhandler = new CallbackHandler() {
                        public void handle(Callback[] callbacks) {
                            for (Callback cb : callbacks) {
                                if (cb instanceof PasswordCallback) {
                                    ((PasswordCallback)cb).setPassword(password);
                                }
                            }
                        }
                    };
                }
                ((AuthProvider)provider).setCallbackHandler(cbhandler);
            }
            final KeyStore.ProtectionParameter fprot = prot;
            final KeyStore.LoadStoreParameter loadParam = new KeyStore.LoadStoreParameter() {
                public KeyStore.ProtectionParameter getProtectionParameter() {
                    return fprot;
                }
            };
            KeyStore keystore = null;
            if (provider == null && path != null) {
                // Next line is Java 9 or later. Java 8 can't combine CallbackHandler and file-based keystores.
                // If you're on Java 8, comment out the below line and uncomment the following two
                keystore = KeyStore.getInstance(new File(base, path), loadParam);       // If Java 8, see below
                // keystore = KeyStore.getInstance(type);
                // keystore.load(new FileInputStream(new File(base, path)), ((KeyStore.PasswordProtection)prot).getPassword());
            } else {
                if (provider == null) {
                    keystore = KeyStore.getInstance(type);
                } else {
                    keystore = KeyStore.getInstance(type, provider);
                }
                keystore.load(loadParam);
            }
            return keystore;
        } catch (IOException e) {
            if (e.getCause() instanceof UnrecoverableKeyException) {
                throw (UnrecoverableKeyException)e.getCause();
            } else if (e.getCause() instanceof LoginException) {
                throw (LoginException)e.getCause();
            }
            throw e;
        }
    }

    private static class SAD {
        final String id;
        final Credential credential;
        final PrivateKey key;
        final long expiry;
        SAD(String id, Credential credential, PrivateKey key) {
            this.id = id;
            this.credential = credential;
            this.key = key;
            this.expiry = System.currentTimeMillis() + 5*60*1000;      // Arbitrary - 5mins
        }
        boolean isExpired() {
            return System.currentTimeMillis() > expiry;
        }
    }

    //----------------------------------------------------------------------------

    private static void usage(String err) {
        final String jar = "java -jar netkeystore-" + Server.class.getPackage().getImplementationVersion();
        if (err != null) {
            System.out.println("ERROR: " + err);
        }
        System.out.println("NetKeyStore v" + Server.class.getPackage().getImplementationVersion());
        System.out.println("Usage: " + jar + " --config <conf.yaml>  (for CLI use)");
        System.out.println("Usage: " + jar + "                       (for GUI use)");
        System.out.println("For details see https://github.com/faceless2/netkeystore");
        System.exit(0);
    }

    private static void guilog(Throwable e) {
        e.printStackTrace();
        StringWriter w = new StringWriter();
        e.printStackTrace(new PrintWriter(w));
        JOptionPane.showMessageDialog(null, w.toString(), "Error", JOptionPane.ERROR_MESSAGE);
    }

    private static boolean gui(final Server server, String userConfigFile) throws Exception {
        final Preferences prefs = Preferences.userNodeForPackage(Server.class);
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
                        InputStream in = null;
                        try {
                            confdetail.setLabel("Configuration: none");
                            listening.setLabel("Not listening");
                            in = new FileInputStream(file);
                            server.configure(in, file);
                            server.start();
                            conf.setEnabled(false);
                            stop.setEnabled(true);
                            stop.setLabel("Stop server");
                            confdetail.setLabel("Configuration: " + file);
                            listening.setLabel("Listening on " + server.getPort());
                            prefs.put("config", file.getPath());
                        } catch (Exception ex) {
                            guilog(ex);
                            prefs.remove("config");
                        } finally {
                            if (in != null) try { in.close(); } catch (Exception e) {}
                        }
                    }
                }
            };

            stop.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        if (server.isStarted()) {
                            server.stop();
                            listening.setLabel("Not listening");
                            stop.setLabel("Start server");
                        } else {
                            server.start();
                            stop.setLabel("Stop server");
                            listening.setLabel("Listening on " + server.getPort());
                        }
                    } catch (Exception ex) {
                        guilog(ex);
                    }
                }
            });

            conf.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        FileDialog chooser = new FileDialog((java.awt.Frame)null);
                        chooser.setVisible(true);
                        String filename = chooser.getFile();
                        if (filename != null) {
                            String directory = chooser.getDirectory();
                            loader.accept(new File(directory, filename));
                        }
                    } catch (Exception ex) {
                        guilog(ex);
                    }
                }
            });

            quit.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        if (server.isStarted()) {
                            server.stop();
                            Thread.sleep(100);
                        }
                    } catch (Exception ex) {}
                    System.exit(0);
                }
            });

            final TrayIcon trayIcon = new TrayIcon(ImageIO.read(Server.class.getResource("data/trayicon.png")), "NetKeyStore");
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
            return true;
        } else {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        String configFile = null;
        Boolean gui = null;
        Server server = new Server();
        if (args.length == 0) {
            if (!gui(server, null)) {
                usage("Unable to start GUI");
            }
        } else {
            for (int i=0;i<args.length;i++) {
                String s = args[i];
                if (s.equals("--config") && i + 1 < args.length && configFile == null) {
                    configFile = args[++i];
                } else if (s.equals("--help") || s.equals("-h")) {
                    usage(null);
                } else {
                    usage("Invalid argument \"" + args[i] + "\"");
                }
            }
            if (configFile == null) {
                usage("No config file specified");
            } else {
                File file = configFile.equals("-") ? null : new File(configFile).getAbsoluteFile();
                InputStream in = file == null ? System.in : new FileInputStream(file);
                server.configure(in, file);
                in.close();
                server.start();
                System.out.println("Listening on " + server.getURL());
            }
        }
    }

}
