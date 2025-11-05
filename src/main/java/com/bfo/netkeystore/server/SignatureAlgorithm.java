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
        List<String> l = new ArrayList<String>(names.length + 1);
        l.add(oid);
        l.addAll(Arrays.asList(names));
        this.names = Collections.<String>unmodifiableList(l);
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
            return "NONEwithECDSA";
        } else if ("ECDSA".equals(ka) || "RSA".equals(ka)) {
            return "NONEwith" + ka;
        } else {
            return name();
        }
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

    public static SignatureAlgorithm get(String name) {
        return REGISTRY.get(name);
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
        register(new SignatureAlgorithm("1.3.101.112", "EdDSA", null, "Ed25519"));
        register(new SignatureAlgorithm("1.3.101.113", "EdDSA", null, "Ed448"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.17", "ML-DSA", null, "ML-DSA-44"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.18", "ML-DSA", null, "ML-DSA-65"));
        register(new SignatureAlgorithm("2.16.840.1.101.3.4.3.19", "ML-DSA", null, "ML-DSA-87"));

        // Notes on new algorithms
        //
        // Conceptually, all signatures work on a hash of the message. For RSA/EC algorithms that
        // hash is done first in one stage, then the signature applied to the hash in a second stage.
        // CSC is designed with those algorithms in mind.
        //
        // More modern algorithms (EdDSA, MLDSA, SLH-DSA) combine the hash and sign operation into one.
        // While there are "pre-hashed" variations of EcDSA and MLDSA at least, they use different OIDs
        // and are neither compatible nor loved, and they also don't solve the problem: they're intended
        // to avoid having to hash a message twice on HSM devices with limited capacity. They don't let
        // you just pass in a hash of the data.
        //
        // We can support algorithms that combine hashiing and signing, , but only by passing ALL the data
        // that needs signing from the client to the server. While this sounds like a terrible idea there
        // are some common uses (eg PKCS#7) where that data is already a hash, so it's not a big deal.
        //
        // Another option would be doing some magic, calculating whatever hash is used by each algorithm on
        // the client, in whatever way is required by each algorithm, then slotting it in at the correct
        // stage on the server. But there are several problems with this:
        //
        // 1. The Java algorithms don't expose anough code to allow this type of approach.
        // 2. While we could rewrite them, it's not going to work with HSMs, which is mostly the point of this API
        // 3. Some of the hash algorithms use private data from the key as an input, so we couldn't even do it
        //    in software.
        //
        // Our only solution: support those algorithms (effectively they work like "NONEwithRSA", the client just
        // sends whatever was given to the signature.update method). But document that we're passing the data
        // across directly.
        // 
        //
        // For posterity here are some notes on investigating option 3
        //
        // * ML-DSA uses SHAKE256. The hash would need to be SHAKE256(SHAKE256(publickey, 64) + message, 64).
        //   Yes, possible with a reimplementation of ML-DSA to allow this value to be passed in.
        //   @see FIP204 value of "tr" property, defined as H(publickey).
        //   @see https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/provider/ML_DSA.java
        //
        // * EdDSA is more complex; for Ed25519 the hash is SHA512(R||Q||M) where M is the message and R is
        //   derived from the private key. So it can't be supported remotely with the current architecture of CSC; would
        //   require multiple passes to exchange info, and this may well leak private data. Will never happen.
        //
        // * SLH-DSA hash is H(R||PK||M) where R is derived from private key and message. As with EcDSA, not going to work.
        //
    }

}
