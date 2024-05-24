package com.bfo.netkeystore;

import java.util.*;
import java.util.function.*;
import java.security.*;
import java.nio.*;
import java.net.*;
import java.io.*;
import java.util.concurrent.*;
import com.bfo.json.*;

class RemoteSupplier {

    private final Engine engine;
    private final String name, host, uri;
    private final Map<String,String> properties;
    private Map<String,KeyStore.Entry> keystore;

    RemoteSupplier(Engine engine, String name, String host, InetSocketAddress address, Map<String,String> properties) {
        this.engine = engine;
        this.name = name;
        this.host = host;
        this.properties = properties;
        boolean secure = "true".equalsIgnoreCase(properties.get("secure"));
        String path = properties.get("path");
        if (path == null) {
            path = "/";
        } else {
            if (path.indexOf("#") >= 0) {
                path = path.substring(0, path.indexOf("#"));
            }
            if (path.indexOf("?") >= 0) {
                path = path.substring(0, path.indexOf("?"));
            }
            if (!path.startsWith("/")) {
                path = "/" + path;
            }
            if (!path.endsWith("/")) {
                path = path + "/";
            }
        }
        uri = (secure ? "https://" : "http://") + address.getHostName() + ":" + address.getPort() + path;
    }

    String getName() {
        return name;
    }

    HttpURLConnection getURLConnection(String suffix) throws IOException {
        if (suffix == null) {
            suffix = "";
        } else if (suffix.startsWith("/")) {
            suffix = suffix.substring(1);
        }
        try {
            URL url = new URI(uri + suffix).toURL();
            HttpURLConnection con = (HttpURLConnection)url.openConnection();
            con.setRequestMethod("POST");
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setConnectTimeout(2000);
            con.setReadTimeout(5000);
            con.setRequestProperty("Content-Type", "application/cbor");
            return con;
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    Map<String,KeyStore.Entry> getKeyStore(KeyStore.ProtectionParameter prot) throws IOException, UnrecoverableKeyException {
        if (keystore == null) {
            keystore = engine.requestKeyStore(this, prot);
        }
        return keystore;
    }

}
