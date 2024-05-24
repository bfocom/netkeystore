package com.bfo.netkeystore;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.nio.charset.*;
import com.bfo.json.*;

class NetPrivateKey implements PrivateKey, Cloneable {

    private final JWK jwk;
    private final RemoteSupplier supplier;
    private final String name, algname;
    private final char[] storepassword;
    private KeyStore.ProtectionParameter protection;

    NetPrivateKey(RemoteSupplier supplier, String name, String algname, JWK jwk, char[] storepassword) {
        this.supplier = supplier;
        this.name = name;
        this.algname = algname;
        this.jwk = jwk;
        this.storepassword = storepassword;
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
        return jwk.toString().getBytes(StandardCharsets.UTF_8);
    }

    RemoteSupplier getRemoteSupplier() {
        return supplier;
    }

    char[] getStorePassword() {
        return storepassword;
    }

    String getName() {
        return name;
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
