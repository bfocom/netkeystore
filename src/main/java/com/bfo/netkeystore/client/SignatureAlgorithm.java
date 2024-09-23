package com.bfo.netkeystore.client;

import java.util.*;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.*;

/**
 * A helper class representing SignatureAlgorithm, with OID, zero or more friendly names and some other helper methods.
 */
public class SignatureAlgorithm {

    private static final Map<String,SignatureAlgorithm> REGISTRY = new HashMap<String,SignatureAlgorithm>();

    private final String keyAlgorithm, digestAlgorithm, oid;
    private final List<String> names;

    private SignatureAlgorithm(String oid, String keyAlgorithm, String digestAlgorithm, String... names) {
        this.oid = oid;
        this.keyAlgorithm = keyAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.names = Collections.<String>unmodifiableList(Arrays.asList(names));
    }

    /**
     * Return true if this SignatureAlgorithm matches the specified name
     * @param name the name
     * @return true if it matches
     */
    public boolean isName(String name) {
        return (oid != null && oid.equals(name)) || names.contains(name);
    }

    /**
     * Return the preferred name - the first one, or the OID if no names are specified
     * @return the name
     */
    public String name() {
        return names.isEmpty() ? oid : names.get(0);
    }

    /**
     * Return the list of all names that match this algorithm
     * @return the list of names
     */
    public List<String> names() {
        return names;
    }

    /**
     * Return the OID for this algorithm
     * @return the OID
     */
    public String oid() {
        return oid;
    }

    /**
     * Return the keyAlgorithm for this algorithm
     * @return the algorithm name
     */
    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    /**
     * Return the digestAlgorithm for this algorithm
     * @return the algorithm name
     */
    public String digestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Return the name of the Java algorithm to use when creating this Signature if an external digest is used
     * @return the algorithm name
     */
    public String signingAlgorithmWithExternalDigest() {
        String ka = keyAlgorithm();
        if ("EC".equals(ka)) {
            ka = "ECDSA";
        }
        return "NONEwith" + ka;
    }

    /**
     * Return the Class to use for this algorithm's {@link AlgorithmParameterSpec}, or null if it has no parameters
     * @return the class, or null
     */
    public Class<? extends AlgorithmParameterSpec> signingAlgorithmParameterClass() {
        return null;
    }

    /**
     * Apply the digest to the signature, which may be as simple as calling sig.update(digest);
     * @param digest the digest
     * @param sig the signature
     * @throws SignatureException if one occurs
     */
    public void sign(byte[] digest, Signature sig) throws SignatureException {
        sig.update(digest);
    }

    /**
     * Return a list of all defined algorithms
     * @return the collection of SignatureAlgorithms
     */
    public static Collection<SignatureAlgorithm> all() {
        return Collections.<SignatureAlgorithm>unmodifiableCollection(REGISTRY.values());
    }

    /**
     * Return the SignatureAlgorithm matching the specified name
     * @param name the name
     * @return the algorithm
     */
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
        register(new SignatureAlgorithm("1.3.101.112", "EdDSA", "SHA-512", "Ed25519"));
        register(new SignatureAlgorithm("1.3.101.113", "EdDSA", "SHAKE256", "Ed448"));
    }

}
