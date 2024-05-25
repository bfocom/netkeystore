package com.bfo.netkeystore;

import java.security.*;
import java.security.cert.*;
import com.bfo.json.*;
import java.io.*;
import java.util.*;
import java.lang.reflect.*;
import java.util.concurrent.*;

public class NetProvider extends Provider {

    public static final String NAME = "NetProvider";
    public static final String KEYSTORE_TYPE = "NetKeyStore";

    private Engine engine;

    NetProvider(Engine engine) {
        super(NAME, "1.0", NAME + " from https://github.com/faceless2/netkeystore");
        String pack = getClass().getPackage().getName();
        putService(new MyService(this, "KeyStore", KEYSTORE_TYPE, pack + ".NetKeyStoreSpi", null, null));
        for (String hash : new String[] { "NONE", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512" }) {
            for (String key : new String[] { "RSA", "ECDSA" }) {
                putService(new MyService(this, "Signature", hash + "with" + key, pack + ".NetSignatureSpi", null, null));
            }
        }
        this.engine = engine;
    }

    public NetProvider() {
        this(null);
    }

    @Override public void load(InputStream in) throws IOException {
        if (engine != null) {
            throw new IllegalStateException("Configured");
        }
        engine = new Engine();
        engine.load(in);
    }

    synchronized Engine getEngine() {
        if (engine == null) {
            engine = new Engine();
            try {
                engine.load(null);
            } catch (IOException e) {}
        }
        return engine;
    }

    @Override public Provider configure(String conf) {
        Engine engine = new Engine();
        try {
            engine.load(new ByteArrayInputStream(conf.getBytes("UTF-8")));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return new NetProvider(engine);
    }

    private static final class MyService extends Provider.Service {
        MyService(NetProvider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes) {
            super(provider, type, algorithm, className, aliases, attributes);
        }
        public Object newInstance(Object o) {
            ((NetProvider)getProvider()).getEngine();
            try {
                return Class.forName(getClassName()).getDeclaredConstructor(Provider.Service.class).newInstance(this);
            } catch (InvocationTargetException  e) {
                if (e.getCause() instanceof RuntimeException) {
                    throw (RuntimeException)e.getCause();
                } else {
                    throw new RuntimeException(e.getCause());
                }
            } catch (Exception e) {
                throw (InvalidParameterException)new InvalidParameterException().initCause(e);
            }
        }
    }

}
