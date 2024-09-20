package com.bfo.netkeystore.server;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import com.bfo.json.*;
import com.bfo.zeroconf.*;
import com.sun.net.httpserver.*;

/**
 * An OAuth2 Authorization that proxies the authorization to another server,
 * then verifies the returned token has the appropriate scope.
 *
 * This is not a full solution! It's a demonstrator
 */
public class OAuth2Authorization extends Authorization {

    private static final String DEFAULT_SCOPE = "service";      // From the spec
    private static final int DEFAULT_REFRESH_INTERVAL = 60;     // Every 60s recheck any access_tokens to see if they're still valid
    private static final int DEFAULT_EXPIRY           = 3600;   // If not told otherwise, tokens expire in an hour
    private static final int PURGECOUNT = 100;
    private String auth_url;            // The URL on the auth server where the user logs in
    private String token_url;           // The URL on the auth server where we swap a grant for an access_token
    private String revoke_url;          // The URL on the auth server where we revoke an access_token
    private String verify_url;          // The URL on the auth server where we query the internal values of the access_token
    private String configScope;
    private String oauth2server;
    private Server server;
    private Json config;
    private int purgeCount;
    private long refreshInterval, defaultExpiry;
    private Map<String,PrincipalProxy> tokens = new HashMap<String,PrincipalProxy>();

    @Override public String type() {
        return "oauth2code";
    }

    @Override public void setServer(Server server) {
        this.server = server;
    }

    @Override public boolean matches(Principal principal, Credential credential) {
        return true;
    }

    @Override public void configure(Json config) {
        this.config = config;
        oauth2server = config.stringValue("server");
        if (oauth2server == null) {
            auth_url = config.stringValue("auth_url");
            token_url = config.stringValue("token_url");
            revoke_url = config.stringValue("revoke_url");
            if (auth_url == null || token_url == null) {
                throw new IllegalStateException("Missing auth_url or token_url");
            }
        }
        verify_url = config.stringValue("verify_url");
        if (verify_url == null) {
            // We need a means of verifying an accessToken!
            // In the future this could be a public key, although we wouldn't
            // be able to check those for revocation.
            throw new IllegalStateException("Missing verify_url");
        }
        refreshInterval = DEFAULT_REFRESH_INTERVAL;
        defaultExpiry = DEFAULT_EXPIRY;
        if (config.isNumber("refresh_interval")) {
            refreshInterval = config.numberValue("refresh_interval").longValue();
            if (refreshInterval < 0 || refreshInterval > 3600) {
                refreshInterval = DEFAULT_REFRESH_INTERVAL;
            }
        }
        if (config.isNumber("default_expiry")) {
            defaultExpiry = config.numberValue("default_expiry").longValue();
            if (defaultExpiry < 60 || defaultExpiry > 365*24*3600) {       // one minute to one year?
                defaultExpiry = DEFAULT_EXPIRY;
            }
        }
        if (config.isString("scope")) {
            configScope = config.stringValue("scope");
            if (configScope.equals("*")) {
                configScope = null;
            }
        } else {
            configScope = DEFAULT_SCOPE;
        }
    }

    @Override public void initialize(HttpServer htserver, String prefix, Json info) {
        if (oauth2server != null) {
            info.put("oauth2", oauth2server);
        } else {
            info.get("methods").put(info.get("methods").size(), "oauth2/authorize");
            info.get("methods").put(info.get("methods").size(), "oauth2/token");
            htserver.createContext(prefix + "oauth2/authorize", new ProxyHandler(auth_url, true));
            htserver.createContext(prefix + "oauth2/token", new ProxyHandler(token_url, false));
            if (revoke_url != null) {
                info.get("methods").put(info.get("methods").size(), "oauth2/revoke");
                htserver.createContext(prefix + "oauth2/token", new ProxyHandler(revoke_url, false));
            }
        }
    }

    @Override public Principal authorize(HttpExchange exchange) throws IOException {
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            auth = auth.substring(7);
            PrincipalProxy proxy;
            synchronized(tokens) {
                if (purgeCount++ == PURGECOUNT) {
                    purgeCount = 0;
                    for (Iterator<PrincipalProxy> i=tokens.values().iterator();i.hasNext();) {
                        if (i.next().isPurged()) {
                            i.remove();
                        }
                    }
                }
                proxy = tokens.get(auth);
                if (proxy == null) {
                    tokens.put(auth, proxy = new PrincipalProxy(auth));
                }
            }
            try {
                return proxy.getPrincipal();
            } catch (Exception e) {
                server.send(exchange, 401, server.createError("access_denied", "Authorization denied: " + e.getMessage(), null), null);
            }
        } else {
            server.send(exchange, 401, server.createError("access_denied", "Missing Bearer Authorization header.", null), null);
        }
        return null;
    }

    private class PrincipalProxy {

        private final String accessToken;
        private Principal principal;
        private long expiry;            // ms the token is expired (it will be purged "refreshInterval" after that time)
        private long approvalExpiry;    // ms the token next needs verifying with the authorization server to see if its been revoked

        PrincipalProxy(String accessToken) {
            this.accessToken = accessToken;
            this.expiry = System.currentTimeMillis() + refreshInterval * 1000;
        }

        synchronized boolean isPurged() {
            return expiry > System.currentTimeMillis() + refreshInterval * 1000;
        }

        synchronized Principal getPrincipal() {
            String err = null;
            if (approvalExpiry < System.currentTimeMillis()) {
                Json json = verifyAccessToken(accessToken);
                if (json != null) {
                    if (principal == null) {
                        principal = createPrincipal(accessToken, json);
                        if (principal == null) {
                            approvalExpiry = Long.MAX_VALUE;
                            expiry = System.currentTimeMillis();
                        }
                    }
                    if (principal != null) {
                        if (json.isBoolean("active") && !json.booleanValue("active")) {
                            // This valid is defined in RFC7662, and it seems unlikely "active:false" would mean anything else for other implementations
                            approvalExpiry = Long.MAX_VALUE;
                            expiry = System.currentTimeMillis();
                            err = "active=false";
                        } else {
                            long exp = 0;       // in seconds
                            try {
                                exp = json.isNumber("exp") ? json.numberValue("exp").longValue() : json.isString("exp") ? Long.parseLong(json.stringValue("exp")) : 0;
                            } catch (Exception e) {}
                            if (exp == 0) {
                                try {
                                    exp = json.isNumber("expires_in") ? json.numberValue("expires_in").longValue() : json.isString("expires_in") ? Long.parseLong(json.stringValue("expires_in")) : Long.MIN_VALUE;
                                    exp = exp == Long.MIN_VALUE ? 0 : System.currentTimeMillis() / 1000 + exp;
                                } catch (Exception e) {}
                                if (exp == 0) {
                                    exp = System.currentTimeMillis() / 1000 + defaultExpiry;
                                }
                            }
                            expiry = exp * 1000;        // in ms
                            approvalExpiry = Math.min(expiry, System.currentTimeMillis() + refreshInterval * 1000);
                        }
                    }
                } else {
                    approvalExpiry = Long.MAX_VALUE;
                    expiry = System.currentTimeMillis();
                }
            }
            if (principal != null && expiry <= System.currentTimeMillis()) {
                throw new IllegalStateException("Authorization code has expired");
            }
            return principal;
        }
    }

    /**
     * A generic HTTP/HTTPS proxy, taking input on one URL and forwarding or redirecting it to another
     */
    private class ProxyHandler implements HttpHandler {
        final String target;
        final boolean redirect;
        /**
         * @param target the target URL
         * @param redirect if true and the input was a GET, send a 302 redirect instead of forwarding
         */
        ProxyHandler(String target, boolean redirect) {
            this.target = target;
            this.redirect = redirect;
        }
        @Override public void handle(HttpExchange exchange) throws IOException {
            InputStream in = null;
            HttpURLConnection con = null;
            try {
                byte[] data = null;
                int code = 0, len = 0;
                if ("GET".equals(exchange.getRequestMethod()) && redirect) {
                    String url = target + "?" + exchange.getRequestURI().getQuery();
                    if (server.isDebug()) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("# RX ");
                        sb.append(exchange.getRequestURI().getPath());
                        sb.append(" → 302 → ");
                        sb.append(url);
                        server.debug(sb.toString());
                    }
                    code = 302;
                    exchange.getResponseHeaders().set("Location", url);
                } else {
                    if (server.isDebug()) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("# RX ");
                        sb.append(exchange.getRequestURI().getPath());
                        sb.append(" → forward → ");
                        sb.append(target);
                        server.debug(sb.toString());
                    }
                    in = exchange.getRequestBody();
                    // We should never receive more than N bytes
                    data = new byte[65535];
                    len = 0;
                    int l;
                    while (len < data.length && (l=in.read(data, len, data.length - len)) >= 0) {
                        len += l;
                    }
                    in.close();
                    in = null;
                    if (len == data.length) {
                        server.send(exchange, 413, server.createError("invalid_request", "Too much data received", null), null);
                        return;
                    }
                    URL url = new URI(target).toURL();
                    con = (HttpURLConnection)url.openConnection();
                    con.setRequestMethod(exchange.getRequestMethod());
                    for (Map.Entry<String,List<String>> e : exchange.getRequestHeaders().entrySet()) {
                        String key = e.getKey();
                        List<String> list = e.getValue();
                        con.setRequestProperty(key, list.get(0));
                        for (int i=1;i<list.size();i++) {
                            con.addRequestProperty(key, list.get(i));
                        }
                    }
                    con.addRequestProperty("X-Forwarded-For", server.getName());
                    if (data.length > 0) {
                        con.setDoOutput(true);
                        con.getOutputStream().write(data, 0, len);
                        con.getOutputStream().close();
                    }
                    code = con.getResponseCode();
                    in = con.getInputStream();
                    len = 0;
                    while (len < data.length && (l=in.read(data, len, data.length - len)) >= 0) {
                        len += l;
                    }
                    in.close();
                    in = null;
                    exchange.getResponseHeaders().clear();
                    for (Map.Entry<String,List<String>> e : con.getHeaderFields().entrySet()) {
                        String key = e.getKey();
                        if (key != null) {
                            switch (key.toLowerCase()) {
                                case "content-type":
                                case "date":
                                case "expires":
                                case "last-modified":
                                case "cache-control":
                                case "server":
                                case "x-forwarded-for":
                                case "accept-range":
                                case "content-encoding":
                                case "etag":
                                case "location":
                                    exchange.getResponseHeaders().put(key, e.getValue());
                                    break;
                            }
                        }
                    }
                    exchange.getResponseHeaders().add("X-Forwarded-For", target);
                }
                try {
                    exchange.sendResponseHeaders(code, data == null || len == 0 ? -1 : len);
                    if (data != null) {
                        exchange.getResponseBody().write(data, 0, len);
                        exchange.getResponseBody().close();
                    }
                } catch (Exception e) {}
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (in != null) { try { in.close(); } catch (Exception e) {} }
                if (con != null) con.disconnect();
            }
        }
    }

    /**
     * <p>
     * Given an access_token from the upstream authorization server, verify its
     * integrity (by RFC7662, or if it's a JWT ideally by verifying its signature against
     * a public key from the server)
     * and return the "payload" it contains, which is expected to include fields
     * at least including "exp" and "scope".
     * Return null if the access_token cannot be verified.
     * </p><p>
     * The default implementation calls the URL specified by "verify_url" in the
     * configuration file.
     * </p>
     * @throws IllegalStateException with a message describing the failure
     */
    protected Json verifyAccessToken(String accessToken) {
        HttpURLConnection con = null;
        InputStream in = null;
        StringBuilder debug = server.isDebug() ? new StringBuilder() : null;
        String urlstring = verify_url;
        if (!urlstring.contains("{TOKEN}")) {
            urlstring += " token={TOKEN}";      // RFC7662
        }
        urlstring = urlstring.replace("{TOKEN}", accessToken).trim();
        try {
            String post = null;
            int ix = urlstring.indexOf(" ");
            if (ix >= 0) {
                urlstring = urlstring.substring(0, ix).trim();
                post = urlstring.substring(ix + 1).trim();
            }
            URL url = new URI(urlstring).toURL();
            if (debug != null) {
                debug.append("TX → ");
                debug.append(urlstring);
                if (post != null) {
                    debug.append(" ");
                    debug.append(post);
                }
            }
            try {
                con = (HttpURLConnection)url.openConnection();
                if (post != null) {
                    con.setDoOutput(true);
                    con.setRequestMethod("POST");
                    byte[] postdata = post.getBytes(StandardCharsets.UTF_8);
                    con.getOutputStream().write(postdata);
                    con.getOutputStream().close();
                }
                int code = con.getResponseCode();
                String restext = null;
                Json res = null;
                in = con.getInputStream();
                int len = 0, l;
                byte[] data = new byte[65535];
                while (len < data.length && (l=in.read(data, len, data.length - len)) >= 0) {
                    len += l;
                }
                in.close();
                in = null;
                try {
                    res = Json.read(new ByteArrayInputStream(data, 0, len));
                } catch (Exception e) {
                    try {
                        restext = new String(data, 0, len, StandardCharsets.UTF_8);
                        throw new IllegalStateException("authority server returned invalid JSON from \"" + url + "\": " + code + " " + restext);
                    } catch (Exception ex) { }
                    throw new IllegalStateException("authority server returned invalid JSON from \"" + url + "\": " + code);
                }
                if (debug != null) {
                    debug.append(" ← ");
                    debug.append(res.toString());
                }
                if (code != 200) {
                    throw new IllegalStateException("authority server returned " + code + " " + res);
                }
                return res;
            } catch (IOException e) {
                throw (IllegalArgumentException)new IllegalStateException("failed reading from authority server \"" + url + "\"").initCause(e);
            }
        } catch (URISyntaxException e) {
            throw new IllegalStateException("invalid authority server \"" + urlstring + "\"");
        } catch (MalformedURLException e) {
            throw new IllegalStateException("invalid authority server \"" + urlstring + "\"");
        } finally {
            if (debug != null) {
                server.debug(debug.toString());
            }
            if (in != null) { try { in.close(); } catch (Exception e) {} }
            if (con != null) { try { con.disconnect(); } catch (Exception e) {} }
        }
    }

    /**
     * Given the content of an access_token that has been verified, confirm that
     * the token is actually appropriate for this service - for example, it should
     * check the "scope", etc.
     * If it's valid, return a new JWT
     * @param json the payload of the access token
     */
    protected Principal createPrincipal(String accessToken, Json json) {
        Principal principal = null;
        String err = null;
        if (configScope != null && !configScope.equals(json.stringValue("scope"))) {
            throw new IllegalStateException("token scope is \"" + json.stringValue("scope") + "\" not \"" + configScope + "\"");
        }
        JWT jwt = null;
        try {
            jwt = new JWT(accessToken);
            // If we were given a JWT, use it only if it is a superset of the Json returned from the auth server,
            // to ensure we don't throw away any data.
            for (Map.Entry<Object,Json> e : json.mapValue().entrySet()) {
                if (e.getValue().equals(jwt.getPayload().get(e.getKey()))) {
                    jwt = null;
                    break;
                }
            }
        } catch (Exception e) { }
        if (jwt == null) {
            jwt = new JWT(json);  // We have Json, we need a Principal, this is obvious (but not necessary) solution
        }
        return jwt;
    }

}
