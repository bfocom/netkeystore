package com.bfo.netkeystore.server;

import java.security.*;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import com.bfo.json.*;
import com.bfo.zeroconf.*;
import com.sun.net.httpserver.*;

/**
 * An implementation of Authorization that supports "basic" authentication.
 */
public class BasicAuthorization extends Authorization {

    private static final int DEFAULT_EXPIRY = 3600;
    // They're signed so we don't really need to keep track of them, we can just
    // cryptographically verify them. But to implement logout, we have to keep track.
    private Map<String,Long> active = new HashMap<String,Long>(); // [token uuid,expiry]
    private Server server;
    private SecretKey key;
    private Json config;
    private int expiry = DEFAULT_EXPIRY;

    /**
     * Returns "basic"
     */
    @Override public String type() {
        return "basic";
    }

    @Override public void setServer(Server server) {
        this.server = server;
    }

    @Override public boolean matches(Principal principal, Credential credential) {
        return true;
    }

    /**
     * The configuration should include a "users" list which contains zero or
     * more objects with properties including "name", "plaintext" and "credentials"
     */
    @Override public void configure(Json config) {
        this.config = config;
        if (config.isNumber("expiry")) {
            expiry = config.numberValue("expiry").intValue();
            if (expiry < 1 || expiry > 365*24*60*60) {
                expiry = DEFAULT_EXPIRY;
            }
        }
    }

    @Override public void initialize(HttpServer htserver, String prefix, Json info) {
        htserver.createContext(prefix + "auth/login", new AuthLoginHandler());
        htserver.createContext(prefix + "auth/logout", new AuthLogoutHandler());
        Json methods = info.get("methods");
        methods.put(methods.size(), "auth/login");
        methods.put(methods.size(), "auth/logout");
    }

    private SecretKey getKey(JWT jwt) {
        String uuid = jwt.getUniqueID();
        if (uuid != null) {
            // Derive the key from the uuid and the server secret so its not reused for different tokens
            byte[] b0 = uuid.getBytes(StandardCharsets.ISO_8859_1);
            byte[] b1 = server.getSecret();
            byte[] bb = new byte[b0.length + b1.length];
            System.arraycopy(b0, 0, bb, 0, b0.length);
            System.arraycopy(b1, 0, bb, b0.length, b1.length);
            return new SecretKeySpec(bb, "HmacSHA256");
        } else {
            return new SecretKeySpec(server.getSecret(), "HmacSHA256");
        }
    }

    @Override public Principal authorize(HttpExchange exchange) throws IOException {
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            auth = auth.substring(7);
            JWT jwt = new JWT(auth);
            SecretKey key = getKey(jwt);
            long now = System.currentTimeMillis();
            if (jwt.verify(key) && jwt.isValidAt(0)) {
                synchronized(active) {
                    if (active.containsKey(jwt.getUniqueID())) {
                        return jwt;
                    }
                }
            }
        }
        server.send(exchange, 401, server.createError("access_denied", "The user, authorization server or remote service denied the request.", null), null);
        return null;
    }

    /**
     * Log out the specified user
     * @param principal the principal
     */
    protected void logout(JWT principal) {
        synchronized(active) {
            active.remove(principal.getUniqueID());
        }
    }

    /**
     * Verify the user/password. If verified, return the list of credentials they can access, or null if they can access all of them.
     * A custom implementation could overrride this method to use an external source for this data
     * @param userid the user
     * @param password the password
     * @return the JWT representing the user, or null if the login details are invalid
     * @throws RuntimeException if the login is invalid
     */
    protected JWT login(String userid, String password) {
        boolean valid = false;
        if (config.isList("users")) {
            Json userlist = config.get("users");
            for (int i=0;i<userlist.size();i++) {
                Json j = userlist.get(i);
                if (userid.equals(j.stringValue("name"))) {
                    if (j.isString("plaintext") && password.equals(j.stringValue("plaintext"))) {
                        valid = true;
                    }
                    break;
                }
            }
        }
        if (valid) {
            JWT jwt = new JWT();
            if (config.isString("issuer_name")) {
                jwt.setIssuer(config.stringValue("issuer_name"));
            } else {
                jwt.setIssuer(server.getName());
            }
            jwt.setSubject(userid);
            jwt.setIssuedAt(System.currentTimeMillis() / 1000);
            jwt.setExpiry(System.currentTimeMillis() / 1000 + expiry);
            byte[] uuid = new byte[12];
            server.getRandom().nextBytes(uuid);
            if (jwt.getUniqueID() == null) {
                jwt.setUniqueID(Base64.getUrlEncoder().encodeToString(uuid));
            }
            jwt.setAudience(Arrays.asList(server.getURL()));
            SecretKey key = getKey(jwt);
            jwt.sign(key);
            synchronized(active) {
                for (Iterator<Long> i=active.values().iterator();i.hasNext();) {
                    long expiry = i.next();
                    if (expiry < System.currentTimeMillis()) {
                        i.remove();
                    }
                }
                active.put(jwt.getUniqueID(), jwt.getExpiry() * 1000);
            }
            return jwt;
        } else {
            return null;
        }
    }

    private class AuthLoginHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = server.receive(exchange);
                if (req != null) {
                    String auth = exchange.getRequestHeaders().getFirst("Authorization");
                    if (auth == null) {
                        server.send(exchange, 401, server.createError("invalid_request", "Missing authentication parameter", null), null);
                    } else {
                        if (auth.startsWith("Basic ")) {
                            try {
                                auth = auth.substring(6);
                                auth = new String(Base64.getDecoder().decode(auth.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
                            } catch (Exception e) {
                                auth = null;
                            }
                        } else {
                            auth = null;
                        }
                        if (auth == null) {
                            server.send(exchange, 400, server.createError("invalid_request", "Malformed authentication parameter", null), null);
                        } else {
                            int ix = auth.indexOf(":");
                            if (ix <= 0) {
                                server.send(exchange, 400, server.createError("invalid_request", "Malformed username-password.", null), null);
                            } else {
                                String userid = auth.substring(0, ix);
                                String password = auth.substring(ix + 1);
                                JWT jwt = login(userid, password);
                                if (jwt != null) {
                                    Json json = Json.read("{}");
                                    if (jwt.getExpiry() != 0) {
                                        json.put("expires_in", jwt.getExpiry() - (System.currentTimeMillis() / 1000));
                                    }
                                    json.put("access_token", jwt.toString());
                                    server.send(exchange, 200, json, null);
                                } else {
                                    server.send(exchange, 400, server.createError("authentication_error", "An error occurred during authentication process", null), null);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class AuthLogoutHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = server.receive(exchange);
                if (req != null) {
                    Principal principal = authorize(exchange);
                    if (principal instanceof JWT) {
                        logout((JWT)principal);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


}
