package com.bfo.netkeystore;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.util.concurrent.*;
import com.bfo.json.*;

public class NetSignatureSpi extends SignatureSpi {

    private final NetProvider provider;
    private final String algo, sigAlgo, digestAlgo;
    private NetPrivateKey privateKey;
    private AlgorithmParameters params;
    private Signature verifySignature;
    private MessageDigest digest;
    private ByteBuffer noneDigest;

    public NetSignatureSpi(Provider.Service service) throws NoSuchAlgorithmException {
        if (!"Signature".equals(service.getType())) {
            throw new IllegalArgumentException();
        }
        this.provider = (NetProvider)service.getProvider();
        this.algo = service.getAlgorithm();
        int ix = algo.indexOf("with");
        String digestAlgo = null, sigAlgo = null;
        // TODO, investigate Ed25519, Ed448 and RSASSA-PSS. Latter is the only one that takes params
        if (ix > 0) {
            digestAlgo = algo.substring(0, ix);
            sigAlgo = algo.substring(ix + 4);
            switch (digestAlgo) {
                case "NONE":
                    digestAlgo = "NONE";
                    break;
                case "SHA224":
                    digestAlgo = "SHA-224";
                    break;
                case "SHA256":
                    digestAlgo = "SHA-256";
                    break;
                case "SHA384":
                    digestAlgo = "SHA-384";
                    break;
                case "SHA512":
                    digestAlgo = "SHA-512";
                    break;
                case "SHA3-224":
                case "SHA3-256":
                case "SHA3-384":
                case "SHA3-512":
                    break;
                default:
                    digestAlgo = null;
            }
            switch (sigAlgo) {
                case "RSA":
                case "ECDSA":
                    break;
                default:
                    sigAlgo = null;
            }
        }
        if (sigAlgo == null || digestAlgo == null) {
            throw new NoSuchAlgorithmException(algo);
        }
        this.sigAlgo = sigAlgo;
        this.digestAlgo = digestAlgo;
        this.digest = "NONE".equals(digestAlgo) ? null : MessageDigest.getInstance(digestAlgo);
        this.noneDigest = "NONE".equals(digestAlgo) ? ByteBuffer.allocate(512) : null;
        for (Provider provider : Security.getProviders()) {
            if (!(provider instanceof NetProvider)) {
                try {
                    this.verifySignature = Signature.getInstance(algo, provider);
                    break;
                } catch (Exception e) {}
            }
        }
    }

    //------------------------------------------------------------------------

    /**
     * @SuppressWarnings("deprecation")
     * @deprecated
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
        String keyAlgo = privateKey.getAlgorithm();
        if (!sigAlgo.equals(keyAlgo)) {
            if (keyAlgo.equals("EC")) {
                keyAlgo = "ECDSA";
            }
            if (!sigAlgo.equals(keyAlgo)) {
                throw new InvalidKeyException("Key is not suitable for " + sigAlgo);
            }
        }
        this.privateKey = (NetPrivateKey)privateKey;
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
     * @SuppressWarnings("deprecation")
     * @deprecated
     */
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException();
    }

    protected void engineSetParameter(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algo);
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
            RemoteSupplier supplier = privateKey.getRemoteSupplier();
            String keyname = privateKey.getName();
            KeyStore.ProtectionParameter prot = privateKey.getProtectionParameter();
            byte[] data;
            if (digest != null) {
                data = digest.digest();
            } else {
                data = new byte[noneDigest.position()];
                noneDigest.flip().get(data);
            }
            return provider.getEngine().requestSignature(supplier, keyname, privateKey.getStorePassword(), prot, sigAlgo, digestAlgo, params, data);
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
