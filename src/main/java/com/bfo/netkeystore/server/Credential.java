package com.bfo.netkeystore.server;

import java.util.*;
import java.security.*;
import java.security.cert.X509Certificate;
import com.bfo.json.*;

/**
 * A Credential is effectively a wrapper around a PrivateKey
 */
interface Credential {

    /**
     * Return the name this Credential is known by for the specified Principal,
     * or null if the Principal has no access to this key
     * @param principal the principal
     * @param userid the "userid" that this anonymous principal specified when listing keys
     * @return a credential id or null
     */
    public String getName(Principal principal, String userid);

    /**
     * Return true if this principal has access to the specified credential id
     * @param principal the principal
     * @param cid the credential id
     * @return true if the credential can be accessed by this principal under that name, false otherwise
     */
    public boolean matches(Principal principal, String cid);

    /**
     * Return the Private Key. Only called after the Credential has been verified by the
     * {@link #match} method, the specified password may be used, ignored or altered depending on the
     * values of local_password and share_password when the Credential was created.
     * @param password the password supplied by the client
     * @return the key or null if access is denied
     */
    public PrivateKey getPrivateKey(String password);

    /**
     * Return the certificates for this Credential
     */
    public List<X509Certificate> getCertificates();

    /**
     * Return the info map for this key that should be returned in credentials/info
     */
    public Json getInfo();

    /**
     * Return the KeyStore this Credential comes from.
     * Not required by the API, it may be useful to a custom {@link KeyAuthorizaton}
     */
    public KeyStore getKeyStore();

    /**
     * Return the name of the KeyStore this Credential comes from.
     * Not required by the API, it may be useful to a custom {@link KeyAuthorizaton}
     */
    public String getKeyStoreName();

    /**
     * Return the name of the KeyStore this Credential comes from.
     * Not required by the API, it may be useful to a custom {@link KeyAuthorizaton}
     */
    public String getKeyStoreAlias();

}
