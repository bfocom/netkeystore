package com.bfo.netkeystore.client;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import java.nio.charset.*;
import com.bfo.json.*;

/**
 * This is the PrivateKey class used by this package.
 * Not public, buy you'll need to use it if your'e implementing a new Server.
 * Intentionally trivial, all implementation-specific properties should be
 * stored in the Json passed into the constructor.
 */
class NetPrivateKey implements PrivateKey, Cloneable {

    private final Server server;
    private final String name, algname;
    private final Json json;
    private KeyStore.ProtectionParameter protection;

    /**
     * Create a new NetPrivateKey
     * @param server the server this key applies to
     * @param name the unique key ID on the server
     * @param algname the Java algorithm name of the key, typically "RSA" or "EC"
     * @param json any extra json data for the key, which can be retrieved from {@link #getJson}.
     */
    NetPrivateKey(Server server, String name, String algname, Json json) {
        this.server = server;
        this.name = name;
        this.algname = algname;
        this.json = json;
    }

    protected Object clone() {
        try {
            return (NetPrivateKey)super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override public String getAlgorithm() {
        return algname;
    }

    @Override public String getFormat() {
        return NetProvider.KEYSTORE_TYPE;
    }

    @Override public byte[] getEncoded() {
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    Server getServer() {
        return server;
    }

    String getName() {
        return name;
    }

    /**
     * Return the Json set on the constructor. Don't modify it!
     */
    Json getJson() {
        return json;
    }

    /**
     * Return a clone of this key with the specified ProtectionParameter set.
     * This is called when the key is retrieved from the KeyStore, and the protection
     * parameter is the value supplied to that method.
     * @param protection the protecton parameter supplied to KeyStore.getKey()
     * @return a duplicate of this key but with that protection parameter
     */
    NetPrivateKey withProtectionParameter(KeyStore.ProtectionParameter protection) {
        NetPrivateKey k = (NetPrivateKey)clone();
        k.protection = protection;
        return k;
    }

    /**
     * Return the ProtectionParameter set in {@link #withProtectionParameter}
     * @return the protection parameters, or null
     */
    KeyStore.ProtectionParameter getProtectionParameter() {
        return protection;
    }

}
