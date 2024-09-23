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

/**
 * A Server represents a network-based signature provider. The configuration for a {@link NetProvider} will
 * generally define one or more Servers, and more may be found via Zeroconf
 */
public interface Server {

    /**
     * Configure the server
     * @param name the server name
     * @param config the configuration
     * @param auto if true, the server has been auto-configured from Zeroconf
     * @throws Exception if the server failed to configure
     */
    public void configure(String name, Json config, boolean auto) throws Exception;

    /**
     * Login to the server. Called from {@link AuthProvider#login}, or the first
     * time a key is requested from its keystore
     * @param subject the subject, or null
     * @param prot the ProtectionParameter used to load the keystore
     * @throws IOException for IOException
     */
    public void login(Subject subject, KeyStore.ProtectionParameter prot) throws IOException;

    /**
     * Log out of the server. Called from {@link AuthProvider#logout}
     * @throws IOException for IOException
     */
    public void logout() throws IOException;

    /**
     * Shut down the server and prepare it for removal from the KeyStore.
     * Only currently used for Zeroconf-originating servers when they go offline
     * @param auto if true, shut the server down only if it was configured with auto=true
     * @return true if the server was shutdown, false if the request was ignored.
     * @throws IOException for IOException
     */
    public boolean shutdown(boolean auto) throws IOException;

    /**
     * Return the SignatureAlgorithm corresponding to the specified name, or null if none exists
     * @param name the signature name, eg "SHA256withRSA"
     * @return the SignatureAlgorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm(String name);

    /**
     * Load the keystore from the Core with keys
     * @throws IOException for IOException
     */
    public void load() throws IOException;

    /**
     * This calls "credentials/authorize" then "signature/hash"
     * @param key the signing key
     * @param algorithm the signature algorithm
     * @param params the signature algorithm params (normally null)
     * @param data the digest to sign
     * @return the signature bytes
     * @throws IOException for IOException
     * @throws UnrecoverableKeyException if the key can't be unlocked
     */
    public byte[] sign(NetPrivateKey key, SignatureAlgorithm algorithm, AlgorithmParameters params, byte[] data) throws UnrecoverableKeyException, IOException;

    /**
     * Given a signature algorithm, return the hash algorithm that should be used to generate the
     * digest for the signature for the specified key, or (if the key is null) if any key owned by
     * this server could support that algorithm.
     * @param key the key that will be used for the signature, or null to check if any key supported by this Server supports the algorithm
     * @param algorithm the signature algorithm as requested by the client
     * @throws InvalidKeyException if the key cannot be used
     */
    public void canSign(NetPrivateKey key, SignatureAlgorithm algorithm) throws InvalidKeyException;

}
