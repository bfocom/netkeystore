package com.bfo.netkeystore.server;

import java.util.*;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.*;

class SignatureAlgorithm {

    private static final Map<String,SignatureAlgorithm> REGISTRY = new HashMap<String,SignatureAlgorithm>();

    private final String keyAlgorithm, digestAlgorithm, oid;
    private final List<String> names;

    private SignatureAlgorithm(String oid, String keyAlgorithm, String digestAlgorithm, String... names) {
        this.oid = oid;
        this.keyAlgorithm = keyAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.names = Collections.<String>unmodifiableList(Arrays.asList(names));
    }

    public boolean isName(String name) {
        return (oid != null && oid.equals(name)) || names.contains(name);
    }

    /**
     * Return the preferred name - the first one, or the OID if no names are specified
     */
    public String name() {
        return names.isEmpty() ? oid : names.get(0);
    }

    public List<String> names() {
        return names;
    }

    public String oid() {
        return oid;
    }

    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    public String digestAlgorithm() {
        return digestAlgorithm;
    }

    public String signingAlgorithmWithExternalDigest() {
        String ka = keyAlgorithm();
        if ("EC".equals(ka)) {
            ka = "ECDSA";
        }
        return "NONEwith" + ka;
    }

    public Class<? extends AlgorithmParameterSpec> signingAlgorithmParameterClass() {
        return null;
    }

    public void sign(byte[] digest, Signature sig) throws SignatureException {
        sig.update(digest);
    }

    public static Collection<SignatureAlgorithm> all() {
        return Collections.<SignatureAlgorithm>unmodifiableCollection(REGISTRY.values());
    }

    public static SignatureAlgorithm get(String s) {
        return REGISTRY.get(s);
    }

    public String toString() {
        return "{\"key\":\"" + keyAlgorithm + "\",\"digest\":\"" + digestAlgorithm + "\",\"oid\":\"" + oid + "\"}";
    }

    public int hashCode() {
        return toString().hashCode();
    }

    public boolean equals(Object o) {
        return o instanceof SignatureAlgorithm && toString().equals(o.toString());
    }

    private static void register(SignatureAlgorithm a) {
        if (a.oid != null) {
            REGISTRY.put(a.oid, a);
        }
        for (String name : a.names) {
            REGISTRY.put(name, a);
        }
    }

    static {
        // RSASSA-PKCS1-v1_5 padding
        // https://datatracker.ietf.org/doc/html/rfc8017#page-47
        // https://stackoverflow.com/questions/69750026/create-sha256withrsa-in-two-steps

        register(new SignatureAlgorithm(null, "RSA", null, "NONEwithRSA"));
        register(new SignatureAlgorithm(null, "ECDSA", null, "NONEwithECDSA"));
        register(new SignatureAlgorithm("1.2.840.113549.1.1.11", "RSA", "SHA-256", "SHA256withRSA") {
            public void sign(byte[] digest, Signature sig) throws SignatureException {
                sig.update(new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 });
                sig.update(digest);
            }
        });
        register(new SignatureAlgorithm("1.2.840.113549.1.1.12", "RSA", "SHA-384", "SHA384withRSA") {
            public void sign(byte[] digest, Signature sig) throws SignatureException {
                sig.update(new byte[] { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00 });
                sig.update(digest);
            }
        });
        register(new SignatureAlgorithm("1.2.840.113549.1.1.13", "RSA", "SHA-512", "SHA512withRSA") {
            public void sign(byte[] digest, Signature sig) throws SignatureException {
                sig.update(new byte[] { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 });
                sig.update(digest);
            }
        });
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.14", "RSA", "SHA3-256", "SHA3-256withRSA"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.15", "RSA", "SHA3-384", "SHA3-384withRSA"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.16", "RSA", "SHA3-512", "SHA3-512withRSA"));
        register(new SignatureAlgorithm("1.2.840.10045.4.3.2", "EC", "SHA-256", "SHA256withECDSA"));
        register(new SignatureAlgorithm("1.2.840.10045.4.3.3", "EC", "SHA-384", "SHA384withECDSA"));
        register(new SignatureAlgorithm("1.2.840.10045.4.3.4", "EC", "SHA-512", "SHA512withECDSA"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.10", "EC", "SHA3-256", "SHA3-256withECDSA"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.11", "EC", "SHA3-384", "SHA3-384withECDSA"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.12", "EC", "SHA3-512", "SHA3-512withECDSA"));
        register(new SignatureAlgorithm("1.3.101.112", "EdDSA", "SHA-512", "Ed25519"));
        register(new SignatureAlgorithm("1.3.101.113", "EdDSA", "SHAKE256", "Ed448"));
    }

}
