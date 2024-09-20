package com.bfo.netkeystore.server;

import java.security.Principal;
import com.bfo.json.Json;
import java.security.PrivateKey;
import com.sun.net.httpserver.*;

/**
 * The KeyAuthorization manages the unlocking strategey for keys. There is one per Server.
 */
public interface KeyAuthorization {

    /**
     * The default "Explicit" KeyAuthorization that uses the password sent by the client to unlock the key
     */
    public static final KeyAuthorization EXPLICIT = new KeyAuthorization() {
        @Override public PrivateKey getPrivateKey(Principal principal, Credential credential, String cid, Json req) {
            String key = req.stringValue("PIN");
            return key == null ? null : credential.getPrivateKey(key);
        }
        @Override public void setKeyInfo(Principal principal, Credential credential, String cid, Json info) {
            info.put("authMode", "explicit");
            info.put("PIN", Json.read("{}"));
            info.get("PIN").put("presence", "true");
            info.get("PIN").put("format", "A");
        }
        @Override public boolean isOTP() {
            return false;
        }
        @Override public void setServer(Server server) {
        }
        @Override public void configure(Json json) {
        }
        @Override public void initialize(HttpServer htserver, String prefix, Json info) {
        }
    };

    /**
     * An "Implicit" KeyAuthorization that uses the password set in the configuration file to unlock the key
     */
    public static final KeyAuthorization IMPLICIT = new KeyAuthorization() {
        @Override public PrivateKey getPrivateKey(Principal principal, Credential credential, String cid, Json req) {
            PrivateKey key = credential.getPrivateKey(null);
            if (key == null) {
                throw new IllegalStateException("local_password not specified for credential \"" + credential + "\"");
            }
            return key;
        }
        @Override public void setKeyInfo(Principal principal, Credential credential, String cid, Json info) {
            info.put("authMode", "implicit");
        }
        @Override public boolean isOTP() {
            return false;
        }
        @Override public void setServer(Server server) {
        }
        @Override public void configure(Json json) {
        }
        @Override public void initialize(HttpServer htserver, String prefix, Json info) {
        }
    };

    /**
     * Set the Server this KeyAuthorization is working for. Will be called on initialization
     * @param server the server
     */
    public void setServer(Server server);

    /**
     * Return the PrivateKey from the credential, or null if the key is not unlocked
     * @param principal the principal
     * @param credential the credential
     * @param cid the credential id
     * @param json the contents of the <code>credentials/authorize</code> method
     * @return the private key, or null if the key is not unlocked
     */
    public PrivateKey getPrivateKey(Principal principal, Credential credential, String cid, Json json);

    /**
     * Configure the KeyAuthorization. The default implementation does nothing
     * @param config the confguration
     */
    public void configure(Json config) throws Exception;

    /**
     * Initialize the HttpServer on startup.
     * @param server the HttpServer to add methods or configure TLS authentication on
     * @param prefix the base prefix for any methods being added - typically this is something like "/csc/v1".
     * @param info a template for the info response, which can have values added to it - for example, adding "auth/login" to the "methods" list
     */
    public void initialize(HttpServer htserver, String prefix, Json info);

    /**
     * Populate the map in the credentials/info request with details for the supplied credential.
     * @param principal the principal
     * @param credential the credential
     * @param cid the credential id
     * @param json the key info map to populate
     */
    public void setKeyInfo(Principal principal, Credential credential, String cid, Json json);

    /**
     * Return true if this an an "OTP" key, false if it's a "PIN"
     * @return true for OTP, false for PIN
     */
    public boolean isOTP();

}
