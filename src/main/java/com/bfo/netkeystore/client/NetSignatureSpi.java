package com.bfo.netkeystore.client;

import java.io.*;
import java.nio.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.util.concurrent.*;
import com.bfo.json.*;

/**
 * A {@link SignatureSpi} that defers the signing process to the {@link Server} object
 */
public class NetSignatureSpi extends SignatureSpi {

    private static final int INIT_PSEUDO_LENGTH = 512;  // More than enough for any hash algorithm
    private final NetProvider provider;
    private final Core core;
    private final SignatureAlgorithm algo;
    private NetPrivateKey privateKey;
    private AlgorithmParameters params;
    private Signature verifySignature;
    private MessageDigest digest;
    private byte[] pseudoDigest;
    private int pseudoDigestLength;

    NetSignatureSpi(Provider.Service service) throws NoSuchAlgorithmException {
        this.provider = (NetProvider)service.getProvider();
        this.core = provider.getCore();
        String algoName = service.getAlgorithm();
        this.algo = provider.getCore().getSignatureAlgorithm(algoName);
        if (algo == null) {
            throw new NoSuchAlgorithmException(algoName);
        }
        algoName = algo.name();
        this.digest = algo.digestAlgorithm() == null ? null : MessageDigest.getInstance(algo.digestAlgorithm());
        this.pseudoDigest = new byte[INIT_PSEUDO_LENGTH];
        for (Provider provider : Security.getProviders()) {
            if (!(provider instanceof NetProvider)) {
                try {
                    this.verifySignature = Signature.getInstance(algoName, provider);
                    break;
                } catch (Exception e) { }
            }
        }
    }

    //------------------------------------------------------------------------

    /**
     * @deprecated
     */
    @SuppressWarnings({"deprecation", "dep-ann"})
    @Deprecated
    @Override protected Object engineGetParameter(String param) {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineGetParameter(\"" + param + "\")");
        throw new InvalidParameterException();
    }

    @Override protected AlgorithmParameters engineGetParameters() {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineGetParameters()");
        return params;
    }

    @Override protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineInitSign(" + privateKey + ", " + random + ")");
        if (!(privateKey instanceof NetPrivateKey)) {
            throw new InvalidKeyException("Key is " + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        final NetPrivateKey key = (NetPrivateKey)privateKey;
        key.getServer().canSign(key, algo);
        this.privateKey = key;
        if (this.digest != null) {
            this.digest.reset();
        } else {
            pseudoDigestLength = 0;
        }
    }

    @Override protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (verifySignature == null) {
            throw new InvalidKeyException("Unable to verify signature with algorithm \"" + publicKey.getAlgorithm() + "\", no local implementation");
        }
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineInitVerify(" + publicKey + ")");
        this.verifySignature.initVerify(publicKey);
        this.privateKey = null;
    }

    /**
     * @deprecated
     */
    @SuppressWarnings({"deprecation", "dep-ann"})
    @Deprecated
    @Override protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException();
    }

    @Override protected void engineSetParameter(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineSetParameter(" + paramSpec + ")");
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algo.oid());
            params.init(paramSpec);
            this.params = params;
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmParameterException("No parameters accepted");
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }

    @Override protected void engineUpdate(byte b) throws SignatureException {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineUpdate(byte)");
        if (privateKey == null) {
            verifySignature.update(b);
        } else if (digest != null) {
            digest.update(b);
        } else if (pseudoDigest != null) {
            expandPseudoDigest(1);
            pseudoDigest[pseudoDigestLength++] = b;
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineUpdate(bytes[" + off + ","+len+" of " + b.length + "])");
        if (privateKey == null) {
            verifySignature.update(b, off, len);
        } else if (digest != null) {
            digest.update(b, off, len);
        } else if (pseudoDigest != null) {
            expandPseudoDigest(len);
            System.arraycopy(b, off, pseudoDigest, pseudoDigestLength, len);
            pseudoDigestLength += len;
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override protected void engineUpdate(ByteBuffer input) {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineUpdate(ByteBuffer with " + input.remaining() + " remaining)");
        if (privateKey == null) {
            try {
                verifySignature.update(input);
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
        } else if (digest != null) {
            digest.update(input);
        } else if (pseudoDigest != null) {
            int len = input.remaining();
            expandPseudoDigest(len);
            input.get(pseudoDigest, pseudoDigestLength, len);
            pseudoDigestLength += len;
        } else {
            throw new IllegalStateException("Not initialized");
        }
    }

    private void expandPseudoDigest(int len) {
        if (pseudoDigestLength + len > pseudoDigest.length) {
            pseudoDigest = Arrays.copyOf(pseudoDigest, Math.max(pseudoDigestLength + len, pseudoDigest.length + (pseudoDigest.length >> 1)));
        }
    }

    @Override protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    @Override protected boolean engineVerify(byte[] b, int off, int len) throws SignatureException {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineVerify(bytes[" + off + ","+len+" of " + b.length + "])");
        if (privateKey != null) {
            throw new SignatureException("Not initialized for verifying");
        } else {
            return verifySignature.verify(b, off, len);
        }
    }
    
    @Override protected byte[] engineSign() throws SignatureException {
        if (core.isDebug("trace")) core.debug("trace", "SignatureSpi.engineSign()");
        if (privateKey == null) {
            throw new SignatureException("Not initialized for signing");
        }
        try {
            Server server = privateKey.getServer();
            byte[] data;
            if (digest != null) {
                data = digest.digest();
            } else {
                data = Arrays.copyOf(pseudoDigest, pseudoDigestLength);
                pseudoDigest = new byte[INIT_PSEUDO_LENGTH];
                pseudoDigestLength = 0;
            }
            return server.sign(privateKey, algo, params, data);
        } catch (UnrecoverableKeyException e) {
            throw new SignatureException(e);
        } catch (IOException e) {
            throw new SignatureException("Network Signature failed", e);
        }
    }

    @Override protected int engineSign(byte[] b, int off, int len) throws SignatureException {
        byte[] sig = engineSign();
        if (b.length > len) {
            throw new IllegalArgumentException("Need " + b.length +" bytes for signature, only given " + len);
        }
        len = b.length;
        System.arraycopy(sig, 0, b, off, len);
        return len;
    }

}
