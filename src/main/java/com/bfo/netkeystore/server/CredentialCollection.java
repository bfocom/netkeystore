package com.bfo.netkeystore.server;

import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import javax.crypto.*;
import java.nio.charset.*;
import com.bfo.json.*;

class CredentialCollection {

    private Server server;
    private Json config;
    private Collection<Credential> credentials;

    CredentialCollection(Server server) {
        this.server = server;
        this.credentials = Collections.<Credential>emptySet();
    }

    /**
     * Return a list of all credential IDs associated with this principal
     * @param principal the principal which may be ANONYMOUS, JWT, an X509Principal or something else
     * @param userid if the principal is anonymous, the userid specified by the client
     */
    List<String> getCredentials(Principal principal, String userid) {
        List<String> names = new ArrayList<String>();
        for (Credential credential : credentials) {
            String name = credential.getName(principal, userid);
            if (name != null) {
                names.add(name);
            }
        }
        return names;
    }

    /**
     * Return the Credential corresponding to the Principal and the cid.
     * If the principal was specified by a userid when getCredentials was called, will simply be ANONYMOUS now
     * @param principal the principal which may be ANONYMOUS, a JWT, an X509Principal or something else.
     * @param cid the credential id
     */
    Credential getCredential(Principal principal, String cid) {
        for (Credential credential : credentials) {
            if (credential.matches(principal, cid)) {
                return credential;
            }
        }
        return null;
    }

    void configure(Json config) throws Exception {
        this.config = config;
        credentials = new ArrayList<Credential>();
        Map<String,String> aliases = new HashMap<String,String>();
        if (config.isMap("aliases")) {
            for (Map.Entry<Object,Json> e : config.mapValue("aliases").entrySet()) {
                String shortname = e.getKey().toString();
                String fullname = e.getValue().stringValue();
                if (fullname != null) {
                    aliases.put(shortname, fullname);
                }
            }
        }
        for (Map.Entry<Object,Json> e : config.mapValue("shares").entrySet()) {
            final String keystoreName = e.getKey().toString();
            Json ksconfig = e.getValue();
            if (!ksconfig.booleanValue("disabled")) {
                final KeyStore keystore = server.loadKeyStore(keystoreName, ksconfig);
                for (Enumeration<String> e2 = keystore.aliases();e2.hasMoreElements();) {
                    final String keyName = e2.nextElement();
                    if (keystore.entryInstanceOf(keyName, KeyStore.PrivateKeyEntry.class)) {
                        Certificate[] certs = keystore.getCertificateChain(keyName);
                        if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                            Json keyconfig = ksconfig.isMap("keys") && ksconfig.get("keys").isMap(keyName) ? ksconfig.get("keys").get(keyName) : Json.read("{}");
                            Json keyinfo = Json.read("{}");
                            keyinfo.put("status", keyconfig.booleanValue("disabled") ? "disabled" : "enabled");
                            Json algolist = Json.read("[]");
                            keyinfo.put("algo", algolist);
                            PublicKey pubkey = certs[0].getPublicKey();
                            if ("RSA".equals(pubkey.getAlgorithm())) {
                                for (SignatureAlgorithm algo : SignatureAlgorithm.all()) {
                                    if ("RSA".equals(algo.keyAlgorithm()) && algo.oid() != null) {
                                        algolist.put(algolist.size(), algo.oid());
                                    }
                                }
                                try {
                                    Cipher cipher = Cipher.getInstance("RSA");
                                    cipher.init(Cipher.ENCRYPT_MODE, (RSAPublicKey)pubkey);
                                    keyinfo.put("len", cipher.getOutputSize(0) * 8);
                                } catch (Exception ex) {}
                            } else {
                                JWK jwk = new JWK(pubkey);
                                if (jwk.isString("crv")) {
                                    String curve = jwk.stringValue("crv");
                                    keyinfo.put("curve", curve);
                                    switch(curve) {
                                        case "P-256": algolist.put(0, SignatureAlgorithm.get("SHA256withECDSA").oid()); break;
                                        case "P-384": algolist.put(0, SignatureAlgorithm.get("SHA384withECDSA").oid()); break;
                                        case "P-521": algolist.put(0, SignatureAlgorithm.get("SHA512withECDSA").oid()); break;
                                        // Not currently supported, an non-trivial.
                                        //  -- see https://datatracker.ietf.org/doc/html/rfc8032
                                        //  -- see https://github.com/str4d/ed25519-java/blob/master/src/net/i2p/crypto/eddsa/EdDSAEngine.java
                                        //  -- see https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/ec/ed/EdDSAParameters.java etc
                                        // case "Ed25519": algolist.put(0, SignatureAlgorithm.get("Ed25519").oid); break;
                                        // case "Ed448": algolist.put(0, SignatureAlgorithm.get("Ed448").oid); break;
                                    }
                                }
                            }
                            if (algolist.size() > 0) {
                                String fullName = keystoreName + "/" + keyName;
                                for (Map.Entry<String,String> e3 : aliases.entrySet()) {
                                    if (e3.getValue().equals(fullName)) {
                                        fullName = e3.getKey();
                                        break;
                                    }
                                }
                                Credential c = new MyCredential(keystore, keystoreName, keyName, fullName, keyconfig, keyinfo);
                                credentials.add(c);
                            }
                        }
                    }
                }
            }
        }
    }

    private boolean isObfuscated() {
        return config.booleanValue("obfuscate_names");
    }

    private boolean isListingDisabled() {
        return config.booleanValue("list_disabled");
    }

    private final class MyCredential implements Credential {
        private final KeyStore keystore;
        private final String keystoreName, alias, fullName;
        private final Json config, info;
        private Map<String,String> anonaliases;
        private List<X509Certificate> certs;

        MyCredential(KeyStore keystore, String keystoreName, String alias, String fullName, Json config, Json info) throws KeyStoreException {
            this.keystore = keystore;
            this.keystoreName = keystoreName;
            this.alias = alias;
            this.fullName = fullName;
            this.config = config;
            this.info = info;
            Certificate[] c = keystore.getCertificateChain(alias);
            List<X509Certificate> certs = new ArrayList<X509Certificate>(c.length);
            for (int i=0;i<c.length;i++) {
                certs.add((X509Certificate)c[i]);
            }
            this.certs = Collections.<X509Certificate>unmodifiableList(certs);
        }
        @Override public KeyStore getKeyStore() {
            return keystore;
        }
        @Override public String getKeyStoreName() {
            return keystoreName;
        }
        @Override public String getKeyStoreAlias() {
            return alias;
        }
        @Override public List<X509Certificate> getCertificates() {
            return certs;
        }

        @Override public String getName(Principal principal, String userid) {
            boolean ok = true;
            if (config != null) {
                if (config.booleanValue("disabled") && isListingDisabled()) {
                    ok = false;
                } else {
                    if (principal.getName() != null) {
                        userid = principal.getName();
                    }
                    if (config.isList("users")) {
                        ok = false;
                        if (userid != null) {
                            Json l = config.get("users");
                            for (int i=0;i<l.size();i++) {
                                if (userid.equals(l.stringValue(i))) {
                                    ok = true;
                                    break;
                                }
                            }
                        }
                    } else if (config.isString("users")) {
                        ok = config.stringValue("users").equals(userid);
                    }
                }
            }
            if (ok && server.getAuthorization().matches(principal, this)) {
                String keyname;
                if (isObfuscated()) {
                    if (principal == Authorization.ANONYMOUS) {
                        synchronized(this) {
                            if (anonaliases == null) {
                                anonaliases = new HashMap<String,String>();
                            }
                            keyname = anonaliases.get(userid);
                            if (keyname == null) {
                                byte[] rand = new byte[12];
                                server.getRandom().nextBytes(rand);
                                keyname = Base64.getUrlEncoder().encodeToString(rand);
                                anonaliases.put(userid, keyname);
                            }
                        }
                    } else {
                        // Derive a name from the principal
                        // This doesn't have to be cryptographically sound, as we authenicate
                        // the principal too. It just has to be one-way and fairly short
                        try {
                            MessageDigest digest = MessageDigest.getInstance("MD5");
                            digest.update(server.getSecret());
                            digest.update(principal.toString().getBytes(StandardCharsets.UTF_8));
                            keyname = Base64.getUrlEncoder().encodeToString(digest.digest());
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                } else {
                    keyname = fullName;
                }
                return keyname;
            } else {
                return null;
            }
        }

        @Override public boolean matches(Principal principal, String cid) {
            boolean ok = true;
            if (config != null) {
                if (config.booleanValue("disabled")) {
                    ok = false;
                } else {
                    String userid = principal.getName();
                    if (config.isList("users")) {
                        ok = false;
                        if (userid != null) {
                            Json l = config.get("users");
                            for (int i=0;i<l.size();i++) {
                                if (userid.equals(l.stringValue(i))) {
                                    ok = true;
                                    break;
                                }
                            }
                        }
                    } else if (config.isString("users")) {
                        ok = config.stringValue("users").equals(userid);
                    }
                }
            }
            if (isObfuscated()) {
                if (principal == Authorization.ANONYMOUS) {
                    synchronized(this) {
                        ok = anonaliases != null && anonaliases.containsValue(cid);
                    }
                } else {
                    try {
                        MessageDigest digest = MessageDigest.getInstance("MD5");
                        digest.update(server.getSecret());
                        digest.update(principal.toString().getBytes(StandardCharsets.UTF_8));
                        String keyname = Base64.getUrlEncoder().encodeToString(digest.digest());
                        ok = cid.equals(keyname);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            } else {
                ok = cid.equals(fullName);
            }
            return ok && server.getAuthorization().matches(principal, this);
        }

        @Override public PrivateKey getPrivateKey(String password) {
            if (config != null) {
                String localPassword = config.stringValue("local_password");
                if (localPassword != null) {
                    String sharePassword = config.stringValue("share_password");
                    password = sharePassword == null || sharePassword.equals(password) ? localPassword : null;
                }
            }
            try {
                return (PrivateKey)keystore.getKey(alias, password == null ? null : password.toCharArray());
            } catch (Exception e) {
                return null;
            }
        }

        @Override public Json getInfo() {
            return info;
        }

        public String toString() {
            return keystoreName + "/" + alias;
        }
    }

}
