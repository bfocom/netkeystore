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

class Engine {

    private static final String SERVICE = "_netkeystore._tcp";
    private Zeroconf zc;
    private Service service;
    private String name;
    private Server server;
    private NetProvider provider;
    private Json config;
    private ZeroconfListener clientListener;
    private Map<String,RemoteSupplier> remoteSuppliers = new ConcurrentHashMap<String,RemoteSupplier>();
    private long initializedAfter;

    Engine() {
    }

    String getName() {
        return name;
    }

    void setProvider(NetProvider provider) {
        this.provider = provider;
    }

    Provider getProvider() {
        if (provider == null) {
            provider = new NetProvider(this);
        }
        return provider;
    }

    //---------------------------------------------------------

    private void startClient(boolean search) {
        if (search) {
            zc.query(SERVICE, null);
            zc.addListener(clientListener = new ZeroconfListener() {
                @Override public void serviceNamed(String type, String name) {
                    if (type.equals(SERVICE)) {
                        zc.query(type, name);
                    }
                }
                @Override public void serviceAnnounced(Service service) {
                    if (SERVICE.equals(service.getType()) && !service.getAddresses().isEmpty()) {
                        InetSocketAddress address = new InetSocketAddress(service.getAddresses().iterator().next(), service.getPort());
                        addRemoteNode(service.getName(), service.getFQDN(), address, service.getText());
                    }
                }
                @Override public void serviceExpired(Service service) {
                    removeRemoteNode(service.getName());
                }
            });
        }
    }

    private void stopClient() {
        if (clientListener != null) {
            zc.removeListener(clientListener);
        }
    }

    private boolean addRemoteNode(String name, String fqdn, InetSocketAddress address, Map<String,String> properties) {
        System.out.println("#add: name="+name);
        RemoteSupplier supplier = new RemoteSupplier(this, name, fqdn, address, properties);
        if (remoteSuppliers.putIfAbsent(name, supplier) == null) {
            return true;
        }
        return false;
    }

    private boolean removeRemoteNode(String name) {
        RemoteSupplier rnode = remoteSuppliers.remove(name);
        if (rnode != null) {
            return true;
        } else {
            return false;
        }
    }

    //---------------------------------------------------------

    void load(InputStream in) throws IOException {
        if (in == null) {
            in = new ByteArrayInputStream("{}".getBytes("UTF-8"));
        }
        // server:{ announce: false, port: 0, "share":[{ "type":"pkcs11", "library":"...", "slotIndex":"" }] },
        // client:{ }
        config = Json.read(new YamlReader().setInput(in));
        Json server = null, client = null;
        boolean serverAnnounce = false, clientSearch = false;
        name = config.stringValue("name");
        if (name == null) {
            name = InetAddress.getLocalHost().getHostName() + "-" + ProcessHandle.current().pid();
        }
        if (config.isMap("server")) {
            server = config.get("server");
            int port = 0;
            if (server.has("port")) {
                if (server.numberValue("port") instanceof Integer) {
                    port = server.intValue("port");
                    if (port < 0 || port > 65535) {
                        throw new IllegalArgumentException("Invalid port " + port);
                    }
                } else {
                    throw new IllegalArgumentException("Invalid port " + server.get("port"));
                }
            }
            if (!server.isBoolean("announce") || server.booleanValue("announce")) {
                serverAnnounce = true;
            }
            if (serverAnnounce && zc == null) {
                zc = new Zeroconf();
            }
            this.server = new Server(this, server);
            boolean secure = false;
            String path = null;
            port = this.server.start(port, secure, path);
            System.out.println("Listening on port " + port);
            if (serverAnnounce) {
                Service.Builder builder = new Service.Builder().setName(name).setType(SERVICE).setPort(port);
                if (secure) {
                    builder.put("secure", "true");
                }
                if (path != null && path.length() > 0) {
                    builder.put("path", path);
                }
                service = builder.build(zc);
                service.announce();
            }
        }

        if (config.isMap("client") || server == null) {
            clientSearch = true;
            /*
            client = config.get("client");
            if (client.isString("server")) {
                // TODO
                clientSearch = false;
            }
            */
            if (clientSearch && zc == null) {
                zc = new Zeroconf();
            }
            startClient(clientSearch);
            initializedAfter = System.currentTimeMillis() + 1000;
        } else {
            initializedAfter = System.currentTimeMillis();;
        }
    }

    //----------------------------------------------------------------------------
    // Comms
    //----------------------------------------------------------------------------

    void processCallbacks(Json req, Json auth, CallbackHandler handler) {
        // auth looks like [ { "type": "password", "prompt": } ]
        Map<Callback,Json> callbacks = new LinkedHashMap<Callback,Json>();
        for (int i=0;i<auth.size();i++) {
            Json j = auth.get(i);
            if (j.isMap() && "password".equals(j.stringValue("type"))) {
                callbacks.put(new PasswordCallback(j.stringValue("prompt") + ": ", true), j);
            }
        }
        Callback[] ca = callbacks.keySet().toArray(new Callback[0]);
        if (handler != null) {
            try {
                handler.handle(ca);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (UnsupportedCallbackException e) {
                e.printStackTrace();
            }
        }
        for (Map.Entry<Callback,Json> e : callbacks.entrySet()) {
            Callback c = e.getKey();
            Json j = e.getValue();
            j.remove("message");
            if (c instanceof PasswordCallback && ((PasswordCallback)c).getPassword() != null) {
                j.put("password", new String(((PasswordCallback)c).getPassword()));
            }
        }
        // auth [ { "type": "password", ... } ]
        // Just a password for now.
        req.put("auth", auth);
    }

    /**
     * Request the KeyStores from all remote suppliers
     */
    Map<String,KeyStore.Entry> requestKeyStores(KeyStore.ProtectionParameter prot) throws IOException, UnrecoverableKeyException {
        // Request the keys from all remotes suppliers.
        long d;
        while ((d=initializedAfter - System.currentTimeMillis()) > 0) {
            try {
                Thread.sleep(d);
            } catch (InterruptedException e) {}
        }
        if (remoteSuppliers.size() == 1) {
            return remoteSuppliers.values().iterator().next().getKeyStore(prot);
        }
        final Map<String,KeyStore.Entry> entries = new LinkedHashMap<String,KeyStore.Entry>();
        final Throwable[] exception = new Throwable[1];
        final CountDownLatch latch = new CountDownLatch(remoteSuppliers.size());
        for (RemoteSupplier s : remoteSuppliers.values()) {
            final RemoteSupplier supplier = s;
            ForkJoinPool.commonPool().execute(new Runnable() {
                public void run() {
                    try {
                        Map<String,KeyStore.Entry> map = supplier.getKeyStore(prot);
                        synchronized(entries) {
                            for (Map.Entry<String,KeyStore.Entry> e : map.entrySet()) {
                                entries.put(supplier.getName() + "." + e.getKey(), e.getValue());
                            }
                        }
                    } catch (Exception e) {
                        synchronized(exception) {
                            if (exception[0] == null) {
                                exception[0] = e;
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (entries.isEmpty() && exception[0] != null) {
            if (exception[0] instanceof IOException) {
                throw (IOException)exception[0];
            } else if (exception[0] instanceof UnrecoverableKeyException) {
                throw (UnrecoverableKeyException)exception[0];
            } else {
                throw (RuntimeException)exception[0];
            }
        }
        return entries;
    }

    Map<String,KeyStore.Entry> requestKeyStore(final RemoteSupplier supplier, final KeyStore.ProtectionParameter prot) throws UnrecoverableKeyException, IOException {
        Json req = Json.read("{}");
        CallbackHandler callbackHandler = null;
        if (prot != null) {
            if (prot instanceof KeyStore.PasswordProtection) {
                char[] password = ((KeyStore.PasswordProtection)prot).getPassword();
                if (password != null) {
                    req.put("auth", Json.read("[]"));
                    req.get("auth").put(0, Json.read("{}"));
                    req.get("auth").get(0).put("type", "password");
                    req.get("auth").get(0).put("password", new String(password));
                }
            } else if (prot instanceof KeyStore.CallbackHandlerProtection) {
                callbackHandler = ((KeyStore.CallbackHandlerProtection)prot).getCallbackHandler();
            }
        }
        Json res = null;
        Map<String,KeyStore.Entry> entries = null;

        HttpURLConnection con = null;
        try {
            System.out.println("TX /list-v1: " + req);
            con = supplier.getURLConnection("/list-v1");
            OutputStream out = con.getOutputStream();
            req.write(new CborWriter().setOutput(out));
            out.close();
            if (con.getResponseCode() == 200) {
                // { "type": "error": "message": "..." }
                // { "type": "list-v1", "keys": { "foo.n": ..., }, "auth": [ {"type":"password", "prompt": "xxx} ] }
                InputStream in = con.getInputStream();
                res = Json.readCbor(in);
                in.close();
                System.out.println("RX /list-v1: " + res);
                String type = res.stringValue("type");
                if ("auth".equals(type) && res.isList("auth") && callbackHandler != null) {
                    con.disconnect();
                    processCallbacks(req, res.get("auth"), callbackHandler);
                    System.out.println("TX /list-v1: " + req);
                    con = supplier.getURLConnection("/list-v1");
                    out = con.getOutputStream();
                    req.write(new CborWriter().setOutput(out));
                    out.close();
                    if (con.getResponseCode() == 200) {
                        in = con.getInputStream();
                        res = Json.readCbor(in);
                        System.out.println("RX /list-v1: " + res);
                        in.close();
                        type = res.stringValue("type");
                    }
                }
                if ("list-v1".equals(type) && res.isMap("keys")) {
                    entries = new LinkedHashMap<String,KeyStore.Entry>();
                    char[] storepassword = null;
                    Json auth = req.get("auth");
                    if (auth != null && auth.isList()) {
                        for (int i=0;i<auth.size();i++) {
                            if (auth.get(i).stringValue("type").equals("password") && auth.get(i).isString("password")) {
                                storepassword = auth.get(i).stringValue("password").toCharArray();
                                break;
                            }
                        }
                    }
                    for (Map.Entry<Object,Json> e : res.mapValue("keys").entrySet()) {
                        String name = e.getKey().toString();
                        String alias = e.getValue().isString("alias") ? e.getValue().remove("alias").stringValue() : name;
                        JWK jwk = new JWK(e.getValue());
                        String kty = jwk.stringValue("kty");
                        PrivateKey key = new NetPrivateKey(supplier, name, kty, jwk, storepassword);
                        if (key != null) {
                            List<X509Certificate> certs = jwk.getCertificates();
                            Certificate[] c = new Certificate[certs.size()];
                            for (int i=0;i<c.length;i++) {
                                c[i] = certs.get(i);
                            }
                            entries.put(alias, new KeyStore.PrivateKeyEntry(key, c));
                        }
                    }
                } else if ("auth".equals(type)) {
                    throw new UnrecoverableKeyException(res.has("auth") ? res.get("auth").toString() : "Unauthorized");
                } else {
                    throw new IOException("Invalid response: " + res);
                }
            } else {
                throw new IOException("HTTP " + con.getResponseCode());
            }
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
        return entries;
    }

    /**
     * Send a signature request
     * @param supplier the supplier to send to
     * @param keyName the name of a Key hosted by that supplier
     * @param prot the protection parameter (password or callback) used to decrypt that key
     * @param keyAlg the key algorithm, eg RSA or RC (not currently used)
     * @param digestAlg the digest algorith, eg SHA256 or SHA1
     * @param digest the digest computed using the specified Digest algorithm
     * @return a Future which will resolve to the digested bytes when completed.
     */
    byte[] requestSignature(final RemoteSupplier supplier, final String keyName, final char[] storePassword, final KeyStore.ProtectionParameter prot, final String sigAlg, final String digestAlg, final AlgorithmParameters params, final byte[] digest) throws IOException, UnrecoverableKeyException {
        // Request signature from a remote supplier.
        // send format is { "key": name, "digest": digest, "digest_alg": alg }
        // return format is { "signature": bytes }
        Json req = Json.read("{}");
        req.put("key", keyName);
        req.put("sig_alg", sigAlg);
        req.put("digest_alg", digestAlg);
        req.put("digest", digest);
        if (params != null) {
            req.put("sig_params", params.getEncoded());
        }
        Json auth = Json.read("[]");
        req.put("auth", auth);
        if (storePassword != null) {
            Json j = Json.read("{}");
            j.put("type", "password");
            j.put("for", keyName.substring(0, keyName.indexOf(".")));       // Presumes supplier has no period!
            j.put("password", new String(storePassword));
            auth.put(auth.size(), j);
        }
        CallbackHandler callbackHandler = null;
        if (prot != null) {
            if (prot instanceof KeyStore.PasswordProtection) {
                char[] password = ((KeyStore.PasswordProtection)prot).getPassword();
                if (password != null) {
                    Json j = Json.read("{}");
                    j.put("type", "password");
                    j.put("for", keyName);
                    j.put("password", new String(password));
                    auth.put(auth.size(), j);
                }
            } else if (prot instanceof KeyStore.CallbackHandlerProtection) {
                callbackHandler = ((KeyStore.CallbackHandlerProtection)prot).getCallbackHandler();
            }
        }
        Json res = null;
        byte[] signature = null;

        HttpURLConnection con = null;
        try {
            con = supplier.getURLConnection("/sign-v1");
            System.out.println("TX /sign-v1: " + req);
            OutputStream out = con.getOutputStream();
            req.write(new CborWriter().setOutput(out));
            out.close();
            if (con.getResponseCode() == 200) {
                // { "type": "error": "message": "..." }
                InputStream in = con.getInputStream();
                res = Json.readCbor(in);
                in.close();
                System.out.println("RX /sign-v1: " + res);
                String type = res.stringValue("type");
                if ("auth".equals(type) && res.isList("auth") && callbackHandler != null) {
                    processCallbacks(req, res.get("auth"), callbackHandler);
                    con.disconnect();
                    System.out.println("TX /sign-v1: " + req);
                    con = supplier.getURLConnection("/sign-v1");
                    out = con.getOutputStream();
                    req.write(new CborWriter().setOutput(out));
                    out.close();
                    if (con.getResponseCode() == 200) {
                        in = con.getInputStream();
                        res = Json.readCbor(in);
                        System.out.println("RX /sign-v1: " + res);
                        in.close();
                        type = res.stringValue("type");
                    }
                }
                if ("sign-v1".equals(type)) {
                    signature = res.bufferValue("signature").array();
                } else if ("auth".equals(type)) {
                    throw new UnrecoverableKeyException(res.has("auth") ? res.get("auth").toString() : "Unauthorized");
                } else {
                    throw new IOException("Invalid response: " + res);
                }
            } else {
                throw new IOException("HTTP " + con.getResponseCode());
            }
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
        return signature;
    }

}
