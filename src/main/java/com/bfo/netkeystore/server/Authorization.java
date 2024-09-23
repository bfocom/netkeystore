package com.bfo.netkeystore.server;

import java.security.*;
import java.security.spec.*;
import java.security.cert.X509Certificate;
import javax.crypto.spec.*;
import java.util.*;
import java.util.concurrent.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import com.bfo.json.*;
import com.bfo.zeroconf.*;
import com.sun.net.httpserver.*;

/**
 * The Authorization manages the authorization of users. There is one per Server.
 */
public abstract class Authorization {

    /** 
     * An anonymous principal.
     */
    public static final Principal ANONYMOUS = new Principal() {
        @Override public String toString() {
            return "{anonymous}";
        }
        @Override public String getName() {
            return null;
        }
    };

    /**
     * The open authorization that allows anyone that is allowed to connect.
     * If the SSL connection used client authentication the Principal is the remote
     * identity, otherwise it is {@link #ANONYMOUS}
     */
    public static final Authorization OPEN = new Authorization() {
        @Override public String type() {
            return "external";
        }
        @Override public Principal authorize(HttpExchange exchange) {
            if (exchange instanceof HttpsExchange) {
                try {
                    return ((HttpsExchange)exchange).getSSLSession().getPeerPrincipal();
                } catch (Exception e) {}
            }
            return ANONYMOUS;
        }
        @Override public void configure(Json config) {
        }
        @Override public void setServer(Server server) {
        }
        @Override public void initialize(HttpServer htserver, String prefix, Json info) {
        }
        @Override public boolean matches(Principal principal, Credential credential) {
            return true;
        }
    };

    /**
     * Set the Server this Authorization is working for
     * @param server the server
     */
    public abstract void setServer(Server server);

    /**
     * Return the type of authorization that should be reported to the client: "external", "basic", "digest", "oauth2", "TLS", or "oauth2client"
     * @return the type
     */
    public abstract String type();

    /**
     * Authorize the HTTP exchange. Return the Principal if authorized and normal processing should 
     * continue, or null if this method has intercepted the exchange and sent a 401 error due to authorization failure.
     * @param exchange the HttpExchange
     * @return the Principal, which may be {@link #ANONYMOUS}, a {@link JWT}, a {@link javax.security.auth.x500.X500Principal} or something else
     * @throws IOException for IOException
     */
    public abstract Principal authorize(HttpExchange exchange) throws IOException;

    /**
     * Configure the Authorization.
     * @param config the server configuration
     * @throws Exception if the configuration was invalid
     */
    public abstract void configure(Json config) throws Exception;

    /**
     * Initialize the HttpServer on startup.
     * @param server the HttpServer to add methods or configure TLS authentication on
     * @param prefix the base prefix for any methods being added - typically this is something like "/csc/v1".
     * @param info a template for the info response, which can have values added to it - for example, adding "auth/login" to the "methods" list
     */
    public abstract void initialize(HttpServer server, String prefix, Json info);

    /**
     * Return true if the specified credential is usable by this user.
     * This is a secondary test to the one built-in to the server, which checks the "users" property on each key.
     * It could be extended to match X.509 certificates on the key to the SSL client certificate, for example.
     * The default implementation always returns true.
     * @param principal the principal
     * @param credential the credential
     * @return true if the key can be used by this principal
     */
    public abstract boolean matches(Principal principal, Credential credential);

}
