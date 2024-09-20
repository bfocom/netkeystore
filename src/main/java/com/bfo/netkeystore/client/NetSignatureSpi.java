package com.bfo.netkeystore.client;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.util.concurrent.*;
import com.bfo.json.*;

public class NetSignatureSpi extends SignatureSpi {

    private final NetProvider provider;
    private final SignatureAlgorithm algo;
    private NetPrivateKey privateKey;
    private AlgorithmParameters params;
    private Signature verifySignature;
    private MessageDigest digest;
    private ByteBuffer noneDigest;

    NetSignatureSpi(Provider.Service service) throws NoSuchAlgorithmException {
        this.provider = (NetProvider)service.getProvider();
        String algoName = service.getAlgorithm();
        this.algo = provider.getCore().getSignatureAlgorithm(algoName);
        if (algo == null) {
            throw new NoSuchAlgorithmException(algoName);
        }
        algoName = algo.name();
        this.digest = algo.digestAlgorithm() == null ? null : MessageDigest.getInstance(algo.digestAlgorithm());
        this.noneDigest = digest == null ? null : ByteBuffer.allocate(512);
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
     * @SuppressWarnings({"deprecation", "dep-ann"})
     * @deprecated
     * @Deprecated
     */
    protected Object engineGetParameter(String param) {
        throw new InvalidParameterException();
    }

    protected AlgorithmParameters engineGetParameters() {
        return params;
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (!(privateKey instanceof NetPrivateKey)) {
            throw new InvalidKeyException("Key is " + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        final NetPrivateKey key = (NetPrivateKey)privateKey;
        key.getServer().canSign(key, algo);
        this.privateKey = key;
        if (this.digest != null) {
            this.digest.reset();
        } else {
            this.noneDigest.clear();
        }
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.verifySignature.initVerify(publicKey);
        this.privateKey = null;
    }

    /**
     * @SuppressWarnings({"deprecation", "dep-ann"})
     * @Deprecated
     * @deprecated
     */
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException();
    }

    protected void engineSetParameter(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
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

    protected void engineUpdate(byte b) throws SignatureException {
        if (privateKey == null) {
            verifySignature.update(b);
        } else if (digest != null) {
            digest.update(b);
        } else if (noneDigest != null) {
            noneDigest.put(b);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (privateKey == null) {
            verifySignature.update(b, off, len);
        } else if (digest != null) {
            digest.update(b, off, len);
        } else if (noneDigest != null) {
            noneDigest.put(b, off, len);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    protected void engineUpdate(ByteBuffer input) {
        if (privateKey == null) {
            try {
                verifySignature.update(input);
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
        } else if (digest != null) {
            digest.update(input);
        } else if (noneDigest != null) {
            noneDigest.put(input);
        } else {
            throw new IllegalStateException("Not initialized");
        }
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    protected boolean engineVerify(byte[] b, int off, int len) throws SignatureException {
        if (privateKey != null) {
            throw new SignatureException("Not initialized for verifying");
        } else {
            return verifySignature.verify(b, off, len);
        }
    }
    
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Not initialized for signing");
        }
        try {
            Server server = privateKey.getServer();
            byte[] data;
            if (digest != null) {
                data = digest.digest();
            } else {
                data = new byte[noneDigest.position()];
                noneDigest.flip().get(data);
            }
            return server.sign(privateKey, algo, params, data);
        } catch (UnrecoverableKeyException e) {
            throw new SignatureException(e);
        } catch (IOException e) {
            throw new SignatureException("Network Signature failed", e);
        }
    }

    protected int engineSign(byte[] b, int off, int len) throws SignatureException {
        byte[] sig = engineSign();
        if (b.length > len) {
            throw new IllegalArgumentException("Need " + b.length +" bytes for signature, only given " + len);
        }
        len = b.length;
        System.arraycopy(sig, 0, b, off, len);
        return len;
    }

}
