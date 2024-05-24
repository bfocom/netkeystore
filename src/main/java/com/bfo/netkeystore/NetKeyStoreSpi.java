package com.bfo.netkeystore;

import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.io.*;

public class NetKeyStoreSpi extends KeyStoreSpi {

    private final NetProvider provider;
    private Map<String,KeyStore.Entry> entries;

    public NetKeyStoreSpi(Provider.Service service) {
        this.provider = (NetProvider)service.getProvider();
    }

    synchronized Map<String,KeyStore.Entry> getEntries() {
        return entries;
    }

    //-----------------------------------------

    @Override public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam) {
        KeyStore.Entry e = getEntries().get(alias);
        if (e instanceof KeyStore.PrivateKeyEntry && protParam != null) {
            NetPrivateKey key = (NetPrivateKey)((KeyStore.PrivateKeyEntry)e).getPrivateKey();
            Certificate[] certs = ((KeyStore.PrivateKeyEntry)e).getCertificateChain();
            e = new KeyStore.PrivateKeyEntry(key.withProtectionParameter(protParam), certs);
        }
        return e;
    }

    @Override public int engineSize() {
        return getEntries().size();
    }

    @Override public Enumeration<String> engineAliases() {
        final Iterator<String> i = getEntries().keySet().iterator();
        return new Enumeration<String>() {
            public boolean hasMoreElements() {
                return i.hasNext();
            }
            public String nextElement() {
                return i.next();
            }
        };
    }

    //-----------------------------------------

    @Override public final boolean engineContainsAlias(String alias) {
        return engineGetEntry(alias, null) != null;
    }
    @Override public final boolean engineEntryInstanceOf(String alias, Class<? extends KeyStore.Entry> entryClass) {
        KeyStore.Entry e = engineGetEntry(alias, null);
        return e != null && entryClass.isAssignableFrom(e.getClass());
    }
    @Override public final Certificate engineGetCertificate(String alias) {
        KeyStore.Entry e = engineGetEntry(alias, null);
        if (e instanceof KeyStore.PrivateKeyEntry) {
            return ((KeyStore.PrivateKeyEntry)e).getCertificate();
        } else if (e instanceof KeyStore.TrustedCertificateEntry) {
            return ((KeyStore.TrustedCertificateEntry)e).getTrustedCertificate();
        } else {
            return null;
        }
    }
    @Override public final Certificate[] engineGetCertificateChain(String alias) {
        KeyStore.Entry e = engineGetEntry(alias, null);
        if (e instanceof KeyStore.PrivateKeyEntry) {
            return ((KeyStore.PrivateKeyEntry)e).getCertificateChain();
        } else if (e instanceof KeyStore.TrustedCertificateEntry) {
            return new Certificate[] { ((KeyStore.TrustedCertificateEntry)e).getTrustedCertificate() };
        } else {
            return null;
        }
    }
    @Override public final String engineGetCertificateAlias(Certificate cert) {
        for (Enumeration<String> i = engineAliases();i.hasMoreElements();) {
            String alias = i.nextElement();
            KeyStore.Entry e = engineGetEntry(alias, null);
            Certificate c = null;
            if (e instanceof KeyStore.PrivateKeyEntry) {
                c = ((KeyStore.PrivateKeyEntry)e).getCertificate();
            } else if (e instanceof KeyStore.TrustedCertificateEntry) {
                c = ((KeyStore.TrustedCertificateEntry)e).getTrustedCertificate();
            }
            if (c == cert) {
                return alias;
            }
        }
        return null;
    }
    @Override public Date engineGetCreationDate(String alias) {
        return null;
    }
    @Override public final Key engineGetKey(String alias, char[] password) {
        KeyStore.Entry e = engineGetEntry(alias, password == null ? null : new KeyStore.PasswordProtection(password));
        if (e instanceof KeyStore.PrivateKeyEntry) {
            return ((KeyStore.PrivateKeyEntry)e).getPrivateKey();
        }
        return null;
    }
    @Override public final boolean engineIsCertificateEntry(String alias) {
        KeyStore.Entry e = engineGetEntry(alias, null);
        return e instanceof KeyStore.TrustedCertificateEntry;
    }
    @Override public final boolean engineIsKeyEntry(String alias) {
        KeyStore.Entry e = engineGetEntry(alias, null);
        return e instanceof KeyStore.PrivateKeyEntry || e instanceof KeyStore.SecretKeyEntry;
    }
    @Override public final void engineLoad(InputStream stream, char[] password) throws IOException {
        engineLoad(password == null ? null : new KeyStore.LoadStoreParameter() {
            public KeyStore.ProtectionParameter getProtectionParameter() {
                return new KeyStore.PasswordProtection(password);
            }
        });
    }
    @Override public final void engineLoad(KeyStore.LoadStoreParameter prot) throws IOException {
        try {
            entries = provider.getEngine().requestKeyStores(prot == null ? null : prot.getProtectionParameter());
        } catch (UnrecoverableKeyException e) {
            throw new IOException(e);
        }
    }
    @Override public final boolean engineProbe(InputStream in) throws IOException {
         return false;
    }
    @Override public final void engineSetCertificateEntry(String alias, Certificate cert) {
        throw new UnsupportedOperationException("Read-only");
    }
    @Override public final void engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam) {
        throw new UnsupportedOperationException("Read-only");
    }
    @Override public final void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException("Read-only");
    }
    @Override public final void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        throw new UnsupportedOperationException("Read-only");
    }
    @Override public final void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException("Read-only");
    }
    @Override public final void engineStore(KeyStore.LoadStoreParameter param) {
        throw new UnsupportedOperationException("Read-only");
    }
    @Override public final void engineDeleteEntry(String name) {
        throw new UnsupportedOperationException("Read-only");
    }
}
