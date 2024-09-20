package com.bfo.netkeystore.client;

import java.net.*;
import java.nio.charset.*;
import javax.net.ssl.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.text.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import javax.crypto.spec.*;
import javax.security.auth.Subject;
import javax.security.auth.x500.*;
import javax.security.auth.callback.*;
import com.bfo.json.*;

class CSCServer implements Server {

    private static final int TIMEOUT = 15;      // seconds
    private final Core core;
    private boolean auto;
    private Collection<SignatureAlgorithm> acceptedAlgorithms;
    private String name;
    private Json config, info;
    private int version;
    private String url;
    private SSLContext clientssl, serverssl;  // clientssl for outbound reqs, serverssl for oauth2 server
    private Authentication auth;
    private HostnameVerifier hostnameVerifier;

    CSCServer(Core core) {
        this.core = core;
        acceptedAlgorithms = new HashSet<SignatureAlgorithm>();
    }

    @Override public void configure(String name, Json config, boolean auto) throws Exception {
        this.auto = auto;
        this.name = name;
        this.config = config;
        this.url = config.stringValue("url");
        this.version = -1; // config.isNumber("version") ? config.numberValue("version").intValue() : -1;

        if (url == null) {
            throw new IllegalArgumentException("URL is null");
        }
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        if (version < 0) {
            int ix = url.indexOf("/csc/v");
            if (ix > 0) {
                try {
                    version = Integer.parseInt(url.substring(ix + 6));
                    url = url.substring(0, ix);
                } catch (Exception e) {}
            }
        }

        // Note that "auto" keystores are ALWAYS connected to without verifying the SSL
        // certificates. Accepting a keystore announced over Zeroconf isn't something you
        // should do in an environment you don't trust anyway, and as they could simply
        // announce themselves as HTTP there's little point in making a fuss over the chain.
        String keystorename =  config.isMap("client") ? config.get("client").stringValue("keystore") : null;
        String password =  config.isMap("client") ? config.get("client").stringValue("password") : null;
        if (auto || "insecure".equals(keystorename)) {
            clientssl = SSLContext.getInstance("TLS");
            clientssl.init(null, new TrustManager[] { new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String auth) { }
                public void checkServerTrusted(X509Certificate[] chain, String auth) { }
                public X509Certificate[] getAcceptedIssuers() { return null; }
            } }, null);
            hostnameVerifier = new HostnameVerifier() {
                public boolean verify(String urlHostname, SSLSession session) { return true; }
            };
        } else if (keystorename != null) {
            KeyStore keystore = core.loadKeyStore(keystorename, password);
            clientssl = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = null;
            if (password != null) {
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keystore, password.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keystore);
            clientssl.init(kmf != null ? kmf.getKeyManagers() : null, tmf.getTrustManagers(), null);
        }
    }

    @Override public boolean shutdown(boolean auto) {
        if (!auto || this.auto) {
            if (auth != null) {
                auth.shutdown();
            }
            return true;
        }
        return false;
    }

    @Override public SignatureAlgorithm getSignatureAlgorithm(String name) {
        for (SignatureAlgorithm algo : acceptedAlgorithms) {
            if (algo.isName(name)) {
                return algo;
            }
        }
        return null;
    }

    private String baseurl() {
        if (this.url == null) {
            throw new IllegalArgumentException("URL not set");
        }
        StringBuilder url = new StringBuilder();
        url.append(this.url);
        if (!this.url.endsWith("/")) {
            url.append("/");
        }
        url.append("csc/v");
        url.append(Integer.toString(version < 0 ? 1 : version));
        url.append('/');
        return url.toString();
    }

    private Reply send(String method, String url, Json json, Authentication auth) throws IOException {
        try {
            String reqh = "", resh = "", sent = "";
            byte[] data = null;
            if (url == null) {
                throw new IllegalArgumentException("URL is null");
            }
            if (!"GET".equals(method) && !"POST".equals(method) && !"OPTIONS".equals(method) && !"HEAD".equals(method) && !"DELETE".equals(method)) {
                throw new IllegalArgumentException("Invalid method");
            }
            HttpURLConnection con = (HttpURLConnection)(new URI(url).toURL().openConnection());
            if (con instanceof HttpsURLConnection && clientssl != null) {
                ((HttpsURLConnection)con).setSSLSocketFactory(clientssl.getSocketFactory());
                if (hostnameVerifier != null) {
                    ((HttpsURLConnection)con).setHostnameVerifier(hostnameVerifier);
                }
            }
            int timeout = config.isNumber("timeout") ? config.numberValue("timeout").intValue() : 0;
            if (timeout < 1) {
                timeout = TIMEOUT;
            }
            con.setConnectTimeout(timeout * 1000);
            con.setReadTimeout(timeout * 1000);
            con.setInstanceFollowRedirects(false);
            if ("POST".equals(method)) {
                con.setDoOutput(true);
                con.setRequestMethod("POST");
                sent = json.toString();
                data = sent.getBytes("UTF-8");
                sent = " " + sent;
            } else if ("DELETE".equals(method)) {
                con.setRequestMethod("DELETE");
            } else {
                // con.setRequestMethod("GET");    // default
            }

            con.setRequestProperty("Accept", "*/*");    // To override default
            con.setRequestProperty("Content-Type", "application/json;charset=utf-8");
            if (data != null) {
                con.setRequestProperty("Content-Length", Integer.toString(data.length));
            }
            if (auth != null) {
                String h = auth.getAuthorization();
                if (h != null) {
                    con.setRequestProperty("Authorization", h);
                }
            }
            if (core.isDebug()) {
                for (Map.Entry<String,List<String>> e : con.getRequestProperties().entrySet()) {
                    if (reqh.length() > 0) {
                        reqh += "; ";
                    }
                    reqh += e.getKey() + ": " + (e.getValue().size() == 1 ? e.getValue().get(0) : e.getValue().toString());
                }
                reqh = " [" + reqh + "]";
            }
            if (data != null) {
                con.getOutputStream().write(data);
            }
            int status = con.getResponseCode();
            InputStream in = con.getErrorStream();
            if (in == null) {
                in = con.getInputStream();
            }
            try {
                json = status == 201 ? null : Json.read(in);
            } catch (Exception e) {
                json = null;
            }
            in.close();
            if (core.isDebug()) {
                for (Map.Entry<String,List<String>> e : con.getHeaderFields().entrySet()) {
                    if (resh.length() > 0) {
                        resh += "; ";
                    }
                    resh += e.getKey() + ": " + (e.getValue().size() == 1 ? e.getValue().get(0) : e.getValue().toString());
                }
                resh = " [" + resh + "]";
                resh = reqh = "";
                core.debug(method + " " + url + reqh + sent+" -> "+status+":" + resh + " " + json);
            }
            Map<String,List<String>> map = new LinkedHashMap<String,List<String>>();
            for (Map.Entry<String,List<String>> e : con.getHeaderFields().entrySet()) {
                map.put(e.getKey() == null ? null : e.getKey().toLowerCase(), e.getValue());
            }
            return new Reply(url, status, map, json);
        } catch (Exception e) {
            throw (IOException)new IOException("Exception from \"" + url + "\"").initCause(e);
        }
    }

    private CallbackHandler createCallbackHandler(KeyStore.ProtectionParameter prot) {
        if (prot instanceof KeyStore.CallbackHandlerProtection) {
            return ((KeyStore.CallbackHandlerProtection)prot).getCallbackHandler();
        } else if (prot instanceof KeyStore.PasswordProtection) {
            return new CallbackHandler() {
                public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
                    for (Callback callback : callbacks) {
                        if (callback instanceof PasswordCallback) {
                            ((PasswordCallback)callback).setPassword(((KeyStore.PasswordProtection)prot).getPassword());
                        } else {
                            throw new UnsupportedCallbackException(callback);
                        }
                    }
                }
            };
        } else {
            return null;
        }
    }

    private Authentication createAuth(String type, KeyStore.ProtectionParameter prot, Json info) throws IOException {
        CallbackHandler handler = createCallbackHandler(prot);
        Authentication auth = null;
        if ("none".equals(type)) {
            auth = new Authentication() {
                public String type() { return "none"; }
                public void login() { }
                public String getAuthorization() { return null; }
            };
        } else if ("basic".equals(type)) {
            String username = null, password = null;
            if (config.isMap("basic")) {
                username = config.get("basic").stringValue("username");
                password = config.get("basic").stringValue("password");
            }
            auth = new BasicAuthentication(username, password != null ? password.toCharArray() : null, handler);
        } else if ("oauth2code".equals(type)) {
            Map<String,Object> props = new LinkedHashMap<String,Object>();
            String url = info != null ? info.stringValue("oauth2") : null;
            String issuerurl = info != null ? info.stringValue("oauth2Issuer") : null;
            if (config.isMap("oauth2")) {
                for (Map.Entry<Object,Json> e : config.mapValue("oauth2").entrySet()) {
                    if (e.getKey() instanceof String) {
                        String key = (String)e.getKey();
                        Json val = e.getValue();
                        if ("url".equals(key)) {
                            if (val.isString() && url == null) {
                                url = val.stringValue();
                            }
                            continue;
                        }
                        if (("client_id".equals(key) || "client_secret".equals(key)) && !val.isString()) {
                            continue;
                        }
                        if (!"url".equals(key)) {
                            if (val.isString() || val.isNumber() || val.isBoolean()) {
                                props.put(key, e.getValue().objectValue());
                            } else if (val.isMap()) {
                                for (Map.Entry<Object,Json> e2 : val.mapValue().entrySet()) {
                                    if (e2.getKey() instanceof String && (e2.getValue().isString() || e2.getValue().isNumber() || e2.getValue().isBoolean())) {
                                        props.put(key + "." + e2.getKey(), e2.getValue().objectValue());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (url != null) {
                final OAuth2 oauth2 = new OAuth2() {
                    @Override public boolean setAuthorization(Map<String,?> properties) {
                        boolean b = super.setAuthorization(properties);
                        if (b) {
                            Json m = core.getAuthorization(name);
                            if (m == null) {
                                m = Json.read("{}");
                            }
                            m.put("oauth2", new Json(properties));
                            core.setAuthorization(name, m);
                            return true;
                        }
                        return false;
                    }
                };
                if (url.endsWith("oauth2/authorize")) {
                    url = url.substring(0, url.length() - 16);
                }
                if (!url.endsWith("/")) {
                    url += "/";
                }
                props.put("debug", core.isDebug());
                props.put("authorization_endpoint", url + "oauth2/authorize");
                props.put("token_endpoint", url + "oauth2/token");
                if (!props.containsKey("scope")) {
                    props.put("scope", "service");
                }
                oauth2.setProperties(props);
                if (core.getAuthorization(name) != null) {
                    Json j = core.getAuthorization(name).get("oauth2");
                    if (j != null) {
                        Map<String,Object> map = new LinkedHashMap<String,Object>();
                        for (Map.Entry<Object,Json> e : j.mapValue().entrySet()) {
                            if (e.getKey() instanceof String && !(e.getValue().isMap() || e.getValue().isList())) {
                                map.put((String)e.getKey(), e.getValue().objectValue());
                            }
                        }
                        oauth2.setAuthorization(map);
                    }
                }
                oauth2.setCallbackHandler(handler);
                oauth2.setSSLContext(clientssl);
                if (serverssl == null && config.isMap("oauth2") && config.get("oauth2").isMap("redirect_server")) {
                    String keystorefile =  config.get("oauth2").get("redirect_server").stringValue("keystore");
                    String password =  config.get("oauth2").get("redirect_server").stringValue("password");
                    if (keystorefile != null && password != null) {
                        try {
                            KeyStore keystore = core.loadKeyStore(keystorefile, password);
                            serverssl = SSLContext.getInstance("TLS");
                            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                            kmf.init(keystore, password.toCharArray());
                            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                            tmf.init(keystore);
                            serverssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
                        } catch (RuntimeException e) {
                            throw e;
                        } catch (IOException e) {
                            throw e;
                        } catch (Exception e) {
                            throw (IOException)new IOException().initCause(e);
                        }
                    }
                    oauth2.setRedirectURLHandler(new OAuth2.SimpleRedirectURLHandler(serverssl));
                } else {
                    oauth2.setRedirectURLHandler(new OAuth2.SimpleRedirectURLHandler());
                }
                auth = new OAuth2Authentication(oauth2);
            }
        } else {
            throw new IllegalArgumentException("Unknown authorization type \"" + type + "\"");
        }
        return auth;
    }

    @Override public void login(Subject subject, KeyStore.ProtectionParameter prot) throws IOException {
        Json json = Json.read("{}");
        if (core.getLang() != null) {
            json.put("lang", core.getLang());
        }
        Reply reply = send("POST", baseurl() + "info", json, null);
        if (reply.code == 200) {
            info = reply.json;
            if (info.isList("authType")) {
                // This block will first try "basic" or "oauth2" of those are offered and configured,
                // and then try "basic" or "oauth2" even if they're not configured.
                for (String type : new String[] { ".basic", ".oauth2code", "basic", "oauth2code" }) {
                    if (type.charAt(0) == '.') {
                        type = type.substring(1);
                        if (type.equals("oauth2code")) {
                            if (!config.isMap("oauth2")) {
                                continue;
                            }
                        } else if (type.equals("basic")) {
                            if (!config.isMap("basic")) {
                                continue;
                            }
                        }
                    }
                    for (int i=0;i<info.get("authType").size();i++) {
                        String t = info.get("authType").stringValue(i);
                        if (type.equals(t)) {
                            auth = createAuth(type, prot, info);
                            if (auth == null) {
                                auth = createAuth("none", prot, info);
                            }
                            break;
                        }
                    }
                    if (auth != null) {
                        break;
                    }
                }
            }
            if (auth == null) {
                auth = createAuth("none", prot, info);
            }
        } else {
            throw new IOException(reply.url + " returned " + reply.code + ": " + reply.json);
        }
    }

    @Override public void logout() throws IOException {
    }

    @Override public void load() throws IOException {
        if (auth == null) {
            throw new IllegalStateException("Not connected");
        }
        auth.login();
        Reply reply = send("POST", baseurl() + "credentials/list", Json.read("{}"), auth);
        if (reply.code == 200 && reply.json.isList("credentialIDs")) {
            Json list = reply.json.get("credentialIDs");
            for (int i=0;i<list.size();i++) {
                String kid = list.stringValue(i);
                Json json = Json.read("{}");
                json.put("credentialID", kid);
                json.put("certificates", "chain");
                json.put("certInfo", true);
                json.put("authInfo", true);
                if (core.getLang() != null) {
                    json.put("lang", core.getLang());
                }
                reply = send("POST", baseurl() + "credentials/info", json, auth);
                json = reply.json;
                if (reply.code == 200 && json.isMap("key") && json.isMap("cert")) {
                    if ("enabled".equals(json.get("key").stringValue("status"))) {
                        final Json algos = json.get("key").get("algo");
                        String keyAlg = null;
                        for (int k=0;k<algos.size();k++) {
                            SignatureAlgorithm algo = SignatureAlgorithm.get(algos.stringValue(k));
                            if (algo != null && algo.keyAlgorithm() != null) {
                                acceptedAlgorithms.add(algo);
                                core.addSignatureAlgorithm(algo);
                                keyAlg = algo.keyAlgorithm();
                            }
                        }
                        if (keyAlg != null) {
                            Json certjson = json.get("cert").get("certificates");
                            Certificate[] certs = new Certificate[certjson.size()];
                            for (int k=0;k<certjson.size();k++) {
                                certs[k] = core.decodeCertificate(certjson.stringValue(k));
                            }
                            json.get("cert").remove("certificates");
                            if (json.get("cert").size() == 0) {
                                json.remove("cert");
                            }
                            PrivateKey key = new NetPrivateKey(this, kid, keyAlg, json);
                            core.addKey(this.name + "/" + kid, new KeyStore.PrivateKeyEntry(key, certs));
                        } else {
                            core.warning("Ignoring key \"" + kid + "\": unrecognised algorithms " + json.get("key").get("algo"));
                        }
                    } else {
//                        core.warning("Ignoring disabled key \"" + kid + "\"");
                    }
                } else {
                    throw new IOException(reply.url + " returned " + reply.code + ": " + reply.json);
                }
            }
        } else if (reply.code == 401) {
            throw (IOException)new IOException(reply.url + " returned " + reply.code + ": " + reply.json).initCause(new UnrecoverableKeyException("Authentication \"" + auth.type() + "\" failed (options were " + info.get("authType") + ")"));
        } else {
            throw new IOException(reply.url + " returned " + reply.code + ": " + reply.json);
        }
    }

    @Override public void canSign(NetPrivateKey key, SignatureAlgorithm algorithm) throws InvalidKeyException {
        String oid = algorithm.oid();
        Json algos = key.getJson().get("key").get("algo");
        if (algos != null) {
            for (int i=0;i<algos.size();i++) {
                if (oid.equals(algos.stringValue(i))) {
                    return;
                }
            }
        }
        throw new InvalidKeyException("Key \"" + key.getName() + "\" is not suitable for \"" + algorithm.name() + "\": allowed values are " + algos);
    }

    /**
     * This calls "credentials/authorize" then "signature/hash"
     * @param algorithm the OID of the signature+hash (required)
     */
    @Override public byte[] sign(NetPrivateKey key, SignatureAlgorithm algorithm, AlgorithmParameters params, byte[] data) throws UnrecoverableKeyException, IOException {
        Authentication auth = this.auth;
        final KeyStore.ProtectionParameter prot = key.getProtectionParameter();
        final Json keyjson = key.getJson();
        final Json json = Json.read("{}");

        if (core.getLang() != null) {
            json.put("lang", core.getLang());
        }

        if ("implicit".equals(keyjson.stringValue("authMode"))) {
            json.put("credentialID", key.getName());
        } else if ("oauth2code".equals(keyjson.stringValue("authMode"))) {
            // The fact we're logged on means we're authenticated, no need to send anything
            OAuth2 oauth2 = ((OAuth2Authentication)auth).oauth2.clone();
            Map<String,Object> props = oauth2.getProperties();
            props.put("scope", "credentials");
            oauth2.setProperties(props);
            oauth2.setCallbackHandler(createCallbackHandler(prot));
            auth = new OAuth2Authentication(oauth2);
        } else {
            json.put("credentialID", key.getName());
            String credType = null, passwordPrompt = null;
            boolean sendotp = false; // config.booleanValue("sendotp");   // not sure we need it
            if (keyjson.isMap("PIN") && !"false".equals(keyjson.get("PIN").stringValue("presence"))) {
                Json j = keyjson.get("PIN");
                credType = "PIN";
                passwordPrompt = j.stringValue("label");
            } else if (keyjson.isMap("OTP") && !"false".equals(keyjson.get("OTP").stringValue("presence"))) {
                Json j = keyjson.get("OTP");
                credType = "OTP";
                passwordPrompt = j.stringValue("label");
                if (j.isString("type")) {
                    sendotp = "online".equals(j.stringValue("type"));
                }
            }
            // if (credType == null && config.isString("credentials-authorize-password")) {     // not sure we need it
            //    credType = config.stringValue("credentials-authorize-password");
            // }
            if (sendotp) {
                send("POST", baseurl() + "credentials/sendOTP", json, auth);
            }
            if (credType != null) {
                CallbackHandler handler = createCallbackHandler(prot);
                if (handler != null) {
                    if (passwordPrompt == null) {
                        passwordPrompt = credType;
                    }
                    PasswordCallback callback = new PasswordCallback(passwordPrompt + ": ", "OTP".equals(credType));
                    try {
                        handler.handle(new Callback[] { callback });
                    } catch (UnsupportedCallbackException e) { }
                    if (callback.getPassword() != null) {
                        json.put(credType, new String(callback.getPassword()));
                    }
                }
            }
        }

        json.put("hash", new String[] { Base64.getEncoder().encodeToString(data) });
        json.put("numSignatures", 1);
        auth.login();
        Reply reply = send("POST", baseurl() + "credentials/authorize", json, auth);
        if (reply.code == 200 && reply.json.isString("SAD")) {
            String sad = reply.json.stringValue("SAD");
            for (Object o : new ArrayList<Object>(json.mapValue().keySet())) {
                if (!"credentialID".equals(o) && !"hash".equals(o)) {
                    json.remove(o);
                }
            }
            json.put("SAD", sad);
            json.put("signAlgo", algorithm.oid());
//            if (hashAlgo != null) {
//                json.put("hashAlgo", hashAlgo);
//            }
            if (params != null) {
                String param64 = Base64.getEncoder().encodeToString(params.getEncoded());
                json.put("signAlgoParams", param64);
            }
            reply = send("POST", baseurl() + "signatures/signHash", json, auth);
            if (reply.code == 200 && reply.json.isList("signatures") && reply.json.get("signatures").isString(0)) {
                String s = reply.json.get("signatures").stringValue(0);
                try {
                    byte[] signature = Base64.getDecoder().decode(s);
                    return signature;
                } catch (Exception e) {
                    throw (IOException)new IOException("Unexpected response to " + reply.url + ": " + reply.json).initCause(e);
                }
            } else if (reply.code == 200) {
                throw new IOException("Unexpected response to " + reply.url + ": " + reply.json);
            } else {
                String msg = reply.json.stringValue("error");
                String desc = reply.json.stringValue("error_description");
                throw new UnrecoverableKeyException(msg + ": " + desc);
            }
        } else if (reply.code == 200) {
            throw new IOException("Unexpected response to " + reply.url + ": " + reply.json);
        } else {
            String msg = reply.json.stringValue("error");
            String desc = reply.json.stringValue("error_description");
            throw new UnrecoverableKeyException(msg + ": " + desc);
        }
    }

    //------------------------------------------------------------------------------

    private static final class Reply {
        final String url;
        final int code;
        final Map<String,List<String>> headers;
        final Json json;
        Reply(String url, int code, Map<String,List<String>> headers, Json json) {
            this.url = url;
            this.code = code;
            this.headers = headers;
            this.json = json;
        }
        public String toString() {
            Json j = Json.read("{}");
            j.put("url", url);
            j.put("code", code);
            j.put("headers", headers);
            if (json != null) {
                j.put("body", json);
            }
            return j.toString();
        }
    }

    private interface Authentication {
        public String type();
        public void login() throws IOException;
        public default void shutdown() { }
        public String getAuthorization() throws IOException;
    }

    private final class BasicAuthentication implements Authentication {
        private final CallbackHandler callbackHandler;
        private String username;
        private char[] password;
        private String accessToken, refreshToken;
        private long expiry;

        BasicAuthentication(String username, char[] password, CallbackHandler callbackHandler) {
            this.username = username;
            this.password = password;
            this.callbackHandler = callbackHandler;
        }

        public String type() {
            return "basic";
        }

        public void login() throws IOException {
            if (System.currentTimeMillis() > expiry) {
                accessToken = null;
            }
            if (accessToken == null) {
                boolean rememberMe = false;     // Don't need it for simple
                Json json = Json.read("{}");
                if (rememberMe) {
                    json.put("rememberMe", true);
                }
                Reply reply = send("POST", baseurl() + "auth/login", json, this);
                if (reply.code != 200) {
                    throw new IOException(reply.url + " returned " + reply.code + ": " + reply.json);
                }
                accessToken = reply.json.stringValue("access_token");
                refreshToken = reply.json.stringValue("refresh_token");
                expiry = (System.currentTimeMillis() + (reply.json.has("expires_in") ? reply.json.intValue("expires_in") : 3600) * 1000) - 5000;
            }
        }

        public String getAuthorization() throws IOException {
            if (accessToken == null) {
                if (callbackHandler != null && (username == null || password == null)) {
                    NameCallback ncb = username == null ? new NameCallback("Name: ") : null;
                    PasswordCallback pcb = password == null ? new PasswordCallback("Password: ", false) : null;
                    Callback[] cb = ncb != null && pcb != null ? new Callback[] { ncb, pcb } : ncb != null ? new Callback[] { ncb } : new Callback[] { pcb };
                    try {
                        callbackHandler.handle(cb);
                    } catch (UnsupportedCallbackException e) {
                        throw (IOException)new IOException("Can't authorize").initCause(e);
                    }
                    if (ncb != null) {
                        username = ncb.getName();
                    }
                    if (pcb != null) {
                        password = pcb.getPassword();
                    }
                }
                if (username != null && password != null) {
                    return "Basic " + Base64.getEncoder().encodeToString((username + ":" + new String(password)).getBytes("UTF-8"));
                } else {
                    return null;
                }
            } else {
                return "Bearer " + accessToken;
            }
        }
    }

    private final class OAuth2Authentication implements Authentication {
        private final OAuth2 oauth2;
        private String accessToken;

        OAuth2Authentication(OAuth2 oauth2) {
            this.oauth2 = oauth2;
        }

        public String type() {
            return "oauth2code";
        }

        public void login() throws IOException {
            accessToken = oauth2.getAccessToken();
        }

        public void shutdown() {
            // oauth2.
        }

        public String getAuthorization() throws IOException {
            return accessToken == null ? null : "Bearer " + accessToken;
        }
    }

}
