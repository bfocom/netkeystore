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

class Server {

    private final boolean debug;
    private final Engine engine;
    private final Json config, shares;
    private HttpServer htserver;

    Server(Engine engine, Json config) {
        this.engine = engine;
        this.config = config;
        this.shares = config.get("shares");
        debug = config.booleanValue("debug");
    }

    int start(int port, String path, final SSLContext ssl) throws IOException {
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
        return htserver.getAddress().getPort();
    }

    void stopServer() throws InterruptedException {
        if (htserver != null) {
            htserver.stop(0);
            htserver = null;
        }
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
                KeyStore.ProtectionParameter prot = null;
                if (req.isList("auth")) {
                    Json auth = req.get("auth");
                    for (int i=0;i<auth.size();i++) {
                        if ("password".equals(auth.get(i).stringValue("type"))) {
                            prot = new KeyStore.PasswordProtection(auth.get(i).stringValue("password").toCharArray());
                            break;
                        }
                    }
                }
                final Json keys = Json.read("{}");
                final Json auth = Json.read("[]");
                for (Map.Entry<Object,Json> e : shares.mapValue().entrySet()) {
                    final String storeName = e.getKey().toString();
                    final Json ksconfig = e.getValue();
                    try {
                        KeyStore keystore = Engine.loadLocalKeyStore(engine.getName(), ksconfig, prot);            // This can't be cached!
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
                    } catch (Exception ex) {
                        if (ex instanceof UnrecoverableKeyException || ex instanceof LoginException) {
                            Json j = Json.read("{}");
                            j.put("type", "password");
                            j.put("prompt", "Password for \"" + storeName + "\"");
                            j.put("message", ex.getMessage());
                            auth.put(auth.size(), j);
                        } else {
                            throw ex;
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
                    for (Map.Entry<Object,Json> e : shares.mapValue().entrySet()) {
                        final String storeName = e.getKey().toString();
                        final Json ksconfig = e.getValue();
                        if (keyname.startsWith(storeName + ".")) {
                            err = "Key \"" + keyname + "\" not found in store";
                            keyname = keyname.substring(storeName.length() + 1);
                            KeyStore.ProtectionParameter storeProt = null, keyProt = null;
                            if (req.isList("auth")) {
                                auth = req.get("auth");
                                for (int pass=0;pass<2;pass++) {
                                    for (int i=0;i<auth.size();i++) {
                                        Json j = auth.get(i);
                                        if ("password".equals(j.stringValue("type")) && j.isString("password")) {
                                            KeyStore.PasswordProtection p = new KeyStore.PasswordProtection(j.stringValue("password").toCharArray());
                                            if (pass == 0) {
                                                if (storeName.equals(j.stringValue("for"))) {
                                                    storeProt = p;
                                                } else if (keyname.equals(j.stringValue("for"))) {
                                                    storeProt = p;
                                                }
                                            } else if (!j.isString("for")) {
                                                if (storeProt == null) {
                                                    storeProt = p;
                                                } else if (keyProt == null) {
                                                    keyProt = p;
                                                }
                                            }
                                        }
                                    }
                                }
                                auth = null;
                            }
                            KeyStore keystore = null;
                            try {
                                keystore = Engine.loadLocalKeyStore(engine.getName(), ksconfig, storeProt);            // This can't be cached!
                            } catch (UnrecoverableKeyException ex) {
                                auth = Json.read("[]");
                                Json j = Json.read("{}");
                                j.put("type", "password");
                                j.put("prompt", "Password for \"" + storeName + "\"");
                                j.put("message", ex.getMessage());
                                auth.put(0, j);
                                err = "auth";
                            }
                            if (keystore != null) {
                                KeyStore.Entry entry = null;
                                try {
                                    entry = keystore.getEntry(keyname, Engine.getPasswordProtection(ksconfig, keyProt != null ? keyProt : storeProt));
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
                                    Provider provider = keystore.getProvider();
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

    //----------------------------------------------------------------------------

    private static void help() {
        System.out.println("Usage: java -jar netkeystore-1.0.jar --config <conf.yaml>");
        System.out.println("For details see https://github.com/faceless2/netkeystore");
        System.exit(0);
    }

    public static void main(String[] args) throws Exception {
        String config = null;
        for (int i=0;i<args.length;i++) {
            String s = args[i];
            if (s.equals("--config") && i+1 < args.length && config == null) {
                config = args[++i];
            } else {
                System.err.println("Invalid argument \"" + args[i] + "\"");
                help();
            }
        }
        if (config == null) {
            help();
        }
        Engine engine = new Engine();
        InputStream in = new FileInputStream(config);
        engine.load(in);
        in.close();
    }

}
