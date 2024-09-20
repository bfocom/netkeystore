package com.bfo.netkeystore.server;

import java.security.Principal;
import com.bfo.json.Json;
import java.security.PrivateKey;
import com.sun.net.httpserver.*;

/**
 * The KeyAuthorizationHandler can be implemented to add support for OTP passwords or implicit
 * key unlocking, eg based on the authorized user
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
     */
    public void setServer(Server server);

    /**
     * Return the password to use to unlock the key, or null if the key is not unlocked
     * @param principal the principal
     * @param cid the credential id
     * @param localPassword the "share_password" (if specified) or "local_password" otherwise set on the key, which may be null
     * @param clientPassword the  OTP or PIN value supplied by the client, which should be be set except for "implicit" passwords
     * @return the password to unlock the key, or null if the key is not unlocked
     */
    public PrivateKey getPrivateKey(Principal principal, Credential credential, String cid, Json json);

    /**
     * Configure the KeyAuthorization. The default implementation does nothing
     */
    public void configure(Json json) throws Exception;

    public void initialize(HttpServer htserver, String prefix, Json info);

    /**
     * For "online" OTP passwords, this method is called to generate the OTP and notify the
     * user of its value
     * @param principal the principal
     * @param cid the credential id
     * @param localPassword the "share_password" (if specified) or "local_password" otherwise set on the key, which may be null
     */
    public default Json getChallenge(Principal principal, Credential credential, String cid, String method, Json json) {
        throw new UnsupportedOperationException("Not implemented for \"" + method + "\"");
    }

    /**
     * Return an optional map of additional properties to set on the credentials/info map for this credential.
     * By default it is null, but properties that may be returned include "label", "description", "provider" and "ID",
     * the last of which is required by the network API for OTP passwords.
     * @param principal the principal
     * @param cid the credential id
     */
    public void setKeyInfo(Principal principal, Credential credential, String cid, Json json);

    public boolean isOTP();

}
