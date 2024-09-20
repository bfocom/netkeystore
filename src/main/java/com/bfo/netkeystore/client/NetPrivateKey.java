package com.bfo.netkeystore.client;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import com.bfo.json.*;

class NetPrivateKey implements PrivateKey, Cloneable {

    private final Server server;
    private final String name, algname;
    private final Json json;
    private KeyStore.ProtectionParameter protection;

    /**
     * @param name the key id
     * @param algname the Java algorithm name of the key
     * @param json the json data for the key
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
        try {
            return json.toString().getBytes("UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);      // Can't happen
        }
    }

    Server getServer() {
        return server;
    }

    String getName() {
        return name;
    }

    Json getJson() {
        return json;
    }

    NetPrivateKey withProtectionParameter(KeyStore.ProtectionParameter protection) {
        NetPrivateKey k = (NetPrivateKey)clone();
        k.protection = protection;
        return k;
    }

    KeyStore.ProtectionParameter getProtectionParameter() {
        return protection;
    }

}
