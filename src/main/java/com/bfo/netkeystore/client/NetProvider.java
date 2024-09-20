package com.bfo.netkeystore.client;

import java.security.*;
import java.security.cert.*;
import javax.security.auth.login.*;
import javax.security.auth.callback.*;
import javax.security.auth.Subject;
import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.*;
import com.bfo.json.Json;
import com.bfo.json.YamlReader;

public class NetProvider extends AuthProvider {

    public static final String NAME = "NetProvider";
    public static final String KEYSTORE_TYPE = "NetKeyStore";

    private final Core core;
    private Set<SignatureAlgorithm> algorithms = new HashSet<SignatureAlgorithm>();
    private boolean configured;
    private CallbackHandler callbackHandler;

    /**
     * Create a new NetProvider
     */
    @SuppressWarnings("deprecation")
    public NetProvider() {
        super(NAME, 1.0, NAME + " from https://github.com/faceless2/netkeystore");
        String pack = getClass().getPackage().getName();
        putService(new MyService(this, "KeyStore", KEYSTORE_TYPE, pack + ".NetKeyStoreSpi", null, null));
        this.core = new Core(this);
    }

    /**
     * Creeate a new NetProvider
     * @param conf the name of the configuration file to load, or the configuration itself.
     * @throws RuntimeException if the configuration cannot be loaded, wrapping IOException
     */
    public NetProvider(String conf) {
        this();
        // Note this constructor is used directly by Java 8
        // conf is the name of a file or the configuration itself. We exclude filenames with newlines and braces so there should be no ambiguity
        InputStream in = null;
        try {
            if (!conf.contains("\n") && !conf.contains("{")) {  // Can't write a valid (for us) Yaml config without one of these
                in = new FileInputStream(conf);
            }
        } catch (Exception e) { }
        if (in == null) {
            in = new ByteArrayInputStream(conf.getBytes(StandardCharsets.UTF_8));
        }
        try {
            load(in);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            try { in.close(); } catch (IOException e) {}
        }
    }

    void addSignatureAlgorithm(SignatureAlgorithm algo) {
        synchronized(algorithms) {
            if (algorithms.add(algo)) {
                String pack = getClass().getPackage().getName();
                putService(new MyService(this, "Signature", algo.oid(), pack + ".NetSignatureSpi", algo.names(), null));
            }
        }
    }

    @Override public void load(InputStream in) throws IOException {
        try {
            synchronized(this) {
                if (!configured) {
                    Json json = Json.read(new YamlReader().setInput(in));
                    core.configure(json);
                    configured = true;
                }
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        } 
    }

    @Override public Provider configure(String conf) {
        // conf is the name of a file or the configuration itself. We exclude filenames with newlines and braces so there should be no ambiguity
        NetProvider dup = new NetProvider(conf);
        dup.callbackHandler = callbackHandler;
        return dup;
    }

    Core getCore() {
        return core;
    }

    // Note - it's possible to use this library with a default configuration
    // so DON'T override isConfigured()
    private synchronized void ensureConfigured() {
        if (!configured) {
            try {
                core.configure((Json)null);
            } catch (Exception e) {     // Won't happen for default config
                throw new RuntimeException(e);
            }
            configured = true;
        }
    }

    @Override public void setCallbackHandler(CallbackHandler handler) {
        this.callbackHandler = handler;
    }

    @Override public void login(Subject subject, CallbackHandler handler) throws LoginException {
        if (handler == null) {
            handler = callbackHandler;
        }
        ensureConfigured();
        if (!core.isConnected()) {
            try {
                core.login(subject, handler == null ? null : new KeyStore.CallbackHandlerProtection(handler));
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw (LoginException)new LoginException("Login failed").initCause(e);
            }
        }
    }

    @Override public void logout() throws LoginException {
        // TODO - revoke any tokens?
        ensureConfigured();
        if (core.isConnected()) {
            try {
                core.logout();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw (LoginException)new LoginException("Logout failed").initCause(e);
            }
        }
    }

    private static final class MyService extends Provider.Service {
        MyService(NetProvider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes) {
            super(provider, type, algorithm, className, aliases, attributes);
        }
        public Object newInstance(Object zzz) {
            NetProvider netprovider = (NetProvider)getProvider();
            netprovider.ensureConfigured();
            try {
                if ("Signature".equals(getType())) {
                    return new NetSignatureSpi(this);
                } else if ("KeyStore".equals(getType())) {
                    return new NetKeyStoreSpi(this);
                } else {
                    return null;
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

}
