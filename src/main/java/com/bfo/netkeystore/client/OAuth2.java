package com.bfo.netkeystore.client;

import java.net.*;
import javax.net.ssl.*;
import javax.net.ssl.*;
import java.security.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import java.util.Base64;
import java.net.*;
import javax.security.auth.callback.*;


/**
 * <p>
 * A standalone OAuth2 authorization class with no external dependencies that supports
 * "authorization", "refresh", "device", "client credentials" and "revoke" flows.
 * </p><p>
 * To use this class with "authorization" flow (the normal one) you'll need to create
 * a {@link RedirectURLHandler} to handle the initial OAuth2 authorization, which makes a callback
 * to a webserver. The {@link SimpleRedirectURLHandler} is an instance of this which creates a
 * transient <code>com.sun.net.httpserver</code> server to process these.
 * </p><p>
 * Configuration is done with two  <code>Map&lt;String,?&gt;</code> objects; <code>properties</code>
 * for fixed properties (eg the URI to connect to) and <code>authorization</code> which contains
 * properties that vary such as the <code>access_token</code>. Fixed properties must be set by
 * calling {@link #setProperties} before {@link #getAuthorization} is called. Properties include:
 * </p>
 * <ul>
 * <li><b>flow</b> - the flow to use, one of "authorization", "device" or "client_credentials". Defaults to "authorization"</li>
 * <li><b>client_id</b> - the <code>client_id</code> to log into the service. If not specified it will be retrieved from the {@link CallbackHandler}</li>
 * <li><b>client_secret</b> - the <code>client_secret</code> to log into the service. If not specified it will be retrieved from the {@link CallbackHandler}</li>
 * <li><b>discovery_uri</b> - the optional service discover URL (see RFC 8414). If specified this can be used to retrieve any missing "endpoint" configuration properties</li>
 * <li><b>token_endpoint</b> - the URL to call for <code>grant_token</code> requests to retrieve an <i>access token</i>. Required</li>
 * <li><b>authorization_endpoint</b> - the URL to call to retrieve an <i>authorization token</i>. Required for the "authorization" flow</li>
 * <li><b>device_authorization_endpoint</b> - the URL to call to retrieve an <i>device_authorization token</i>. Required for the "device verification" flow</li>
 * <li><b>redirect_uri</b> - the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2">redirection endpoint URL</a> which will be preregistered with the OAuth2 service - for example <code>http://localhost/oauth2</code>. Required for the "authorization" flow</li>
 * <li><b>final_uri</b> - the URL to send the user to after after authorization has completed. Optional for the "authorization" flow, defaults to "about:blank"</li>
 * <li><b>scope</b> - the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scope token</a>, a single string with one or more words seperated by spaces. Optional, but almost always required</li>
 * <li><b>authorization_inline</b> a boolean, if true the <code>client_id</code> and <code>client_secret</code> will be sent in the request body instead of as an <code>Authorization</code> header</li>
 * <li><b>protocol.auth.<i>nnn</i></b> - any extra strings to be included in requests to the "authorization_endpoint" (key is <i>nnn</i>)</li>
 * <li><b>protocol.grant.refresh_token.<i>nnn</i></b> - any extra strings to be included in any <code>grant_type=refresh_token</code> requests to the "token_endpoint" (key is <i>nnn</i>)</li>
 * <li><b>protocol.grant.code.<i>nnn</i></b> - any extra strings to be included in any <code>grant_type=code</code> requests to the "token_endpoint" (key is <i>nnn</i>)</li>
 * <li><b>protocol.grant.client_credentials.<i>nnn</i></b> - any extra strings to be included in any <code>grant_type=client_credentials</code> requests to the "token_endpoint" (key is <i>nnn</i>)</li>
 * <li><b>protocol.grant.device_verification.<i>nnn</i></b> - any extra strings to be included in any <code>grant_type=device_verification</code> requests to the "token_endpoint" (key is <i>nnn</i>)</li>
 * <li><b>protocol.grant.device_code.<i>nnn</i></b> - any extra strings to be included in any <code>grant_type=urn:ietf:params:oauth:grant-type:device_code</code> requests to the "token_endpoint" (key is <i>nnn</i>)</li>
 * </ul>
 *
 * <h3>Example use</h3>
 * <pre>
 * OAuth2 oauth = new OAuth2() {
 *   public boolean setAuthorization(Map&gt;String,?&gt; p) {
 *     if (super.setAuthorization(p)) {
 *       // save the access_token to local storage
 *     }
 *   }
 * };
 * oauth2.setRedirectURLHandler(new OAuth2.SimpleRedirectURLHandler());
 * oauth2.setCallbackHandler(new com.sun.security.auth.callback.TextCallbackHandler());
 * Map&lt;String,Object&gt; props = new HashMap&lt;String,Object&gt;();
 * props.put("client_id", "123123.apps.googleusercontent.com");
 * props.put("client_secret", "12323123");
 * props.put("redirect_uri", "http://localhost:1234/authorize");
 * props.put("discovery_uri", "https://accounts.google.com/.well-known/openid-configuration");
 * props.put("scope", "openid");
 * oauth2.setProperties(props);
 * Map&lt;String,String&gt; authmap = oauth2.getAuthorization());
 * String accessToken = (String)authmap.get("access_token");
 * </pre>
 */
public class OAuth2 implements Cloneable {

    private static final String STRING_NOW = "__now";
    private static final String STRING_EXPIRY = "__expiry";
    private static final int FLOW_AUTHORIZATION = 0, FLOW_DEVICE = 1, FLOW_CLIENTCREDENTIALS = 2;
    private static final int DATASIZE = 32768;
    private int flow = FLOW_AUTHORIZATION;
    private Map<String,Object> props, authprops;
    private boolean inlineAuthorization;
    private SSLContext ssl;
    private RedirectURLHandler redirectHandler;
    private CallbackHandler callbackHandler;
    private boolean debug;
    private int timeout = 15*1000, trantimeout = 5*60*1000;
    private Random random;

    /**
     * Create a new OAuth2
     */
    public OAuth2() {
        this.authprops = new LinkedHashMap<String,Object>();
        this.props = Collections.<String,Object>emptyMap();
    }

    /**
     * Duplicate an OAuth2
     */
    @Override public OAuth2 clone() {
        try {
            OAuth2 dup = (OAuth2)super.clone();
            if (authprops != null) {
                dup.authprops = new LinkedHashMap<String,Object>(authprops);
            }
            return dup;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Set the {@link RedirectURLHandler} which will be used for "authorization" flow.
     * Required only if that flow is used and a new authorization has to be made
     */
    public void setRedirectURLHandler(RedirectURLHandler handler) {
        this.redirectHandler = handler;
    }

    /**
     * Set the {@link CallbackHandler} which will be called with
     * {@link NameCallback}, {@link PasswordCallback} or {@link TextOutputCallback}
     * object to prompt for missing client_id or client_secret, or to prompt
     * the user to open a URL to complete authorization
     * @param handler the CallbackHandler
     */
    public void setCallbackHandler(CallbackHandler handler ) {
        this.callbackHandler = handler;
    }

    /**
     * Set the SSLContext which will be used for all network traffic
     */
    public void setSSLContext(SSLContext ssl) {
        this.ssl = ssl;
    }

    /**
     * Return the RedirectURLHandler
     */
    public RedirectURLHandler getRedirectURLHandler() {
        return redirectHandler;
    }

    /**
     * Return the CallbackHandler
     */
    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    /**
     * Return the SSLContext
     */
    public SSLContext getSSLContext() {
        return ssl;
    }

    /**
     * Return the Random
     */
    public Random getRandom() {
        if (random == null) {
            try {
                random = SecureRandom.getInstance("NativePRNGNonBlocking");
            } catch (NoSuchAlgorithmException e) {
                random = new SecureRandom();
            }
        }
        return random;
    }

    /**
     * Set the Random used by this object (must not be null)
     * @param random the random to use
     */
    public void setRandom(Random random) {
        if (random == null) {
            throw new IllegalArgumentException("Random cannot be null");
        }
        this.random = random;
    }

    private static String getString(Map<String,?> props, String key, String def) {
        Object o = props == null ? null : props.get(key);
        return o instanceof String ? (String)o : def;
    }
    private static boolean getBoolean(Map<String,?> props, String key, boolean def) {
        Object o = props == null ? null : props.get(key);
        if (o instanceof Boolean) {
            return ((Boolean)o).booleanValue();
        } else if ("true".equals(o)) {
            return true;
        } else if ("false".equals(o)) {
            return false;
        } else {
           return def;
        }
    }
    private static int getInt(Map<String,?> props, String key, int def) {
        if (key.equals(STRING_EXPIRY)) {
            int expiry = getInt(props, "expires_in", 0);
            if (expiry != 0) {
                int now = getInt(props, STRING_NOW, 0);
                expiry = now == 0 ? 0 : expiry + now;
            }
            return expiry;
        } else {
            Object o = props == null ? null : props.get(key);
            if (o instanceof Number) {
                return ((Number)o).intValue();
            } else if (o instanceof String) {
                try {
                    return Integer.parseInt((String)o);
                } catch (Exception e) {}
            }
            return def;
        }
    }

    int getTimeout() {
        return timeout;
    }

    int getTransactionTimeout() {
        return trantimeout;
    }

    /**
     * Reset the OAuth2 with new properties, and resets the Authorization properties
     * @param properties the properties
     */
    public synchronized void setProperties(Map<String,?> properties) {
        authprops = null;
        Map<String,Object> props = new LinkedHashMap<String,Object>();
        for (Map.Entry<String,?> e : properties.entrySet()) {
            if (e.getKey() != null && e.getValue() != null) {
                props.put(e.getKey(), e.getValue());
            }
        }
        inlineAuthorization = getBoolean(props, "authorization_inline", false);
        debug = getBoolean(props, "debug", false);
        String f = getString(props, "flow", "authorization").replaceAll("_-", " ").toLowerCase();
        if ("device".equals(f)) {
            flow = FLOW_DEVICE;
        } else if ("client credentials".equals(f)) {
            flow = FLOW_CLIENTCREDENTIALS;
        } else if ("authorization".equals(f)) {
            flow = FLOW_AUTHORIZATION;
        } else {
            throw new IllegalArgumentException("Invalid flow \"" + f + "\", must be \"authorization\", \"device\" or \"client credentials\"");
        }
        this.props = Collections.<String,Object>unmodifiableMap(props);
    }

    /**
     * Return a copy of the properties set in {@link #setProperties}
     * @return a copy of the properties
     */
    public synchronized Map<String,Object> getProperties() {
        return new LinkedHashMap<String,Object>(props);
    }

    /**
     * Update the OAuth2 with new authorization properties.
     * An overridden instance of this class could save the authorizations if <code>super.setAuthorizations()</code> returned true
     * @return false if this was the first time the authorization properties were called, true if they've been updated
     */
    public synchronized boolean setAuthorization(Map<String,?> auth) {
        boolean ret;
        if (authprops == null) {
            authprops = new LinkedHashMap<String,Object>();
            ret = false;
        } else {
            ret = true;
        }
        if (auth != null) {
            authprops.clear();
            for (Map.Entry<String,?> e : auth.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    authprops.put(e.getKey(), e.getValue());
                }
            }
        }
        return ret;
    }

    /**
     * Notify the user that they have to open a URL. The default implementation
     * calls the callback handle with a {@link TextOutputHandler} if specified,
     * or prints to System.out if not
     * @param url the URL to open
     * @param code an option code that has to be entered when the URL is loaded (for device authorization)
     */
    protected void notifyURL(String url, String code) {
        url = url == null ? null : url.trim();
        code = code == null ? null : code.trim();
        try {
            CallbackHandler handler = getCallbackHandler();
            if (handler != null) {
                if (code != null && code.length() > 0) {
                    url = url + " " + code;
                }
                handler.handle(new Callback[] { new TextOutputCallback(TextOutputCallback.INFORMATION, url) });
                return;
            }
        } catch (Exception e) {
            System.out.println("Authorize: " + url);
        }
    }

    private void debug(String debug) {
        System.out.println(debug);
    }
    private void log(Exception e) {
        e.printStackTrace();
    }

    private static String encodeURL(Map<String,Object> map) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String,Object> e : map.entrySet()) {
            String key = e.getKey();
            String val = e.getValue() == null ? null : e.getValue().toString();
            if (key != null && val != null) {
                if (sb.length() > 0) {
                    sb.append(first ? '?' : '&');
                }
                first = false;
                sb.append(key);
                sb.append('=');
                sb.append(URLEncoder.encode(val, StandardCharsets.UTF_8));
            }
        }
        return sb.toString();
    }

    private String randomString(int len) {
        Random random = getRandom();
        char[] c = new char[len];
        for (int i=0;i<c.length;i++) {
            c[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(random.nextInt(62));
        }
        return new String(c);
    }

    /**
     * Return the "access_token" from the {@link #getAuthorization} method.
     */
    public String getAccessToken() throws IOException {
        Map<String,Object> map = getAuthorization();
        return getString(map, "access_token", null);
    }

    /**
     * Return the authorization response from the OAuth2 server, updating it if necessary - this method may block.
     * The returned Json should have "access_token" and other properties returned from the server. 
     * If the authorization was changed from last time this method was called {@link #setAuthorization} will be
     * called with the updated values (so an overridden instance of this class can save them).
     */
    public synchronized Map<String,Object> getAuthorization() throws IOException {
        if (props.isEmpty()) {
            throw new IllegalStateException("Not configured: call setProperties first");
        }
        if (this.authprops == null) {
            setAuthorization(null);
        }
        final Map<String,Object> authprops = new LinkedHashMap<String,Object>(this.authprops);
        int expiry = getInt(props, STRING_EXPIRY, 0);
        if (expiry != 0 && System.currentTimeMillis() / 1000 > expiry) {
            authprops.remove("access_token");
            authprops.remove("token_type");
        }
        String access_token = getString(authprops, "access_token", null);
        String refresh_token = getString(authprops, "refresh_token", null);

        if (access_token == null) {
            // Make sure we have client_id and client_secret set
            String token_endpoint = getString(props, "token_endpoint", null);
            if (token_endpoint == null) {
                String disco_uri = getString(props, "discovery_uri", null);
                if (disco_uri != null) {
                    Map<String,Object> m = send(disco_uri, "GET", null);
                    Map<String,Object> newprops = new HashMap<String,Object>(props);
                    newprops.put("token_endpoint", getString(props, "token_endpoint", getString(m, "token_endpoint", null)));
                    newprops.put("authorization_endpoint", getString(props, "authorization_endpoint", getString(m, "authorization_endpoint", null)));
                    newprops.put("device_authorization_endpoint", getString(props, "device_authorization_endpoint", getString(m, "device_authorization_endpoint", null)));
                    newprops.put("revocation_endpoint", getString(props, "revocation_endpoint", getString(m, "revocation_endpoint", null)));
                    // others aren't needed for now.
                    props = Collections.<String,Object>unmodifiableMap(newprops);
                    token_endpoint = getString(props, "token_endpoint", null);
                }
                if (token_endpoint == null) {
                    throw new IllegalStateException("Missing \"token_endpoint\" property");
                }
            }
            String client_id = getString(authprops, "client_id", getString(props, "client_id", null));
            String client_secret = getString(authprops, "client_secret", getString(props, "client_secret", null));
            if ((client_id == null || client_secret == null) && getCallbackHandler() != null) {
                NameCallback ncb = client_id == null ? new NameCallback("Client-ID: ") : null;
                PasswordCallback pcb = client_secret == null ? new PasswordCallback("Client-Secret: ", false) : null;
                Callback[] cb = ncb != null && pcb != null ? new Callback[] { ncb, pcb } : ncb != null ? new Callback[] { ncb } : new Callback[] { pcb };
                try {
                    getCallbackHandler().handle(cb);
                } catch (UnsupportedCallbackException e) { }
                if (client_id == null) {
                    client_id = ncb.getName();
                    authprops.put("client_id", client_id);
                }
                if (client_secret == null) {
                    char[] pw = pcb.getPassword();
                    client_secret = pw == null ? null : new String(pw);
                    authprops.put("client_secret", client_secret);
                }
            }
            if (client_id == null && client_secret == null) {
                throw new IllegalStateException("Missing \"client_id\" and \"client_secret\" property");
            } else if (client_id == null) {
                throw new IllegalStateException("Missing \"client_id\" property");
            } else if (client_secret == null) {
                throw new IllegalStateException("Missing \"client_secret\" property");
            }

            Map<String,Object> m = null;
            if (flow == FLOW_AUTHORIZATION) {
                if (refresh_token != null) {
                    m = send(token_endpoint, "grant.refresh_token", null,
                      "grant_type", "refresh_token",
                      "client_id", client_id,
                      "client_secret", client_secret,
                      "refresh_token", refresh_token,
                      "scope", getString(props, "scope", null)
                    );
                    if (m.containsKey("access_token")) {
                        authprops.putAll(m);
                    } else {
                        authprops.put("refresh_token", refresh_token = null);
                    }
                }
                if (refresh_token == null) {
                    m = sendAuthorizationCode(client_id);
                    m = send(token_endpoint, "grant.code", m,
                      "grant_type", "authorization_code",
                      "client_id", client_id,
                      "client_secret", client_secret,
                      "redirect_uri", getString(props, "redirect_uri", null)
                    );
                    if (m.containsKey("access_token")) {
                        authprops.putAll(m);
                    }
                }
            } else if (flow == FLOW_CLIENTCREDENTIALS) {
                m = send(token_endpoint, "grant.client_credentials", null,
                  "grant_type", "client_credentials",
                  "client_id", client_id,
                  "client_secret", client_secret,
                  "scope", getString(authprops, "scope", getString(props, "scope", null))
                );
                if (m.containsKey("access_token")) {
                    authprops.putAll(m);
                }
            } else if (flow == FLOW_DEVICE) {
                String dv_uri = getString(props, "device_authorization_endpoint", null);
                m = send(dv_uri, "device_verification", null,
                  "client_id", client_id,
                  "scope", getString(authprops, "scope", getString(props, "scope", null))
                );
                if (getString(m, "verification_url_complete", null) != null) {
                    notifyURL(getString(m, "verification_url_complete", null), null);
                } else {
                    notifyURL(getString(m, "verification_url", null), getString(m, "user_code", null));
                }
                expiry = getInt(m, STRING_EXPIRY, 0);
                int interval = getInt(m, "interval", 0);
                if (interval <= 0 || interval > 120) {
                    interval = getInt(props, "interval", 5);
                }
                expiry = Math.min(expiry, (int)(System.currentTimeMillis() / 1000) + getTransactionTimeout());
                String device_code = getString(m, "device_code", null);
                if (device_code == null) {
                    throw new IllegalStateException("No \"device_code\" in response");
                }
                boolean polling = true;
                do {
                    m = send(token_endpoint, "grant.device_code", null,
                      "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                      "client_id", client_id,
                      "client_secret", client_secret,
                      "device_code", device_code
                    );
                    String err = getString(m, "error", null);
                    if ("authorization_pending".equals(err)) {
                        try {
                            Thread.sleep(interval * 1000);
                        } catch (InterruptedException e) {
                            break;
                        }
                        m = null;
                    } else if ("slow_down".equals(err)) {
                        interval++;
                    } else if (err != null) {
                        break;
                    }
                } while (m == null && System.currentTimeMillis() / 1000 < expiry);
                if (m == null) {
                    throw new IOException("Timeout");
                }
            }
        }
        authprops.remove(null);
        boolean changed = false;
        for (Map.Entry<String,Object> e : authprops.entrySet()) {
            changed |= !e.getValue().equals(this.authprops.get(e.getKey()));
        }
        for (String key : this.authprops.keySet()) {
            changed |= !authprops.containsKey(key);
        }
        if (changed) {
            setAuthorization(authprops);
        }
        return authprops;
    }

    /**
     * POST data, parse the response as JSON, return it in a map. The null key is the response code
     * @param protocol if not null, the "protocol.NNN" prefix to add properties for from the property map
     * @param props if not null, this map will be added to the send properties
     * @param extra a sequence of key/value pairs to add to the send properties
     */
    private Map<String,Object> send(String url, String protocol, Map<String,Object> reqprops, String... extra) throws IOException {
        final boolean get = "GET".equals(protocol);
        Map<String,Object> m = new LinkedHashMap<String,Object>();
        for (int i=0;i<extra.length;) {
            String key = extra[i++];
            String val = extra[i++];
            if (key != null && val != null) {
                m.put(key, val);
            }
        }
        if (reqprops != null) {
            for (Map.Entry<String,Object> e : reqprops.entrySet()) {
                if (e.getKey() != null && e.getValue() != null && !e.getKey().startsWith("__")) {
                    m.put(e.getKey(), e.getValue());
                }
            }
        }
        if (protocol != null && !get) {
            String prefix = "protocol." + protocol;
            for (Map.Entry<String,Object> e : props.entrySet()) {
                if (e.getKey().startsWith(prefix) && e.getValue() != null) {
                    String key = e.getKey().substring(prefix.length());
                    m.put(key, e.getValue());
                }
            }
        }
        String client_id = null, client_secret = null;
        if (!inlineAuthorization && m.containsKey("client_secret") && m.containsKey("client_id")) {
            client_id = (String)m.remove("client_id");
            client_secret = (String)m.remove("client_secret");
        }
        if (m.containsKey("inline_client_secret")) {
            m.put("client_secret", m.remove("inline_client_secret"));
        }
        if (m.containsKey("inline_client_id")) {
            m.put("client_id", m.remove("inline_client_id"));
        }
        String data = encodeURL(m);
        StringBuilder debugbuf = debug ? new StringBuilder() : null;

        if (get && data.length() > 0) {
            url = url + data;
        }
        HttpURLConnection con = (HttpURLConnection)new URL(url).openConnection();
        if (con instanceof HttpsURLConnection && getSSLContext() != null) {
            ((HttpsURLConnection)con).setSSLSocketFactory(getSSLContext().getSocketFactory());
        }
        con.setRequestMethod(get ? "GET" : "POST");
        con.setDoOutput(!get);
        if (client_id != null && client_secret != null) {
            String s = "Basic " + Base64.getEncoder().encodeToString((client_id + ":" + client_secret).getBytes("UTF-8"));
            con.setRequestProperty("Authorization", s); // Basic auth uses non-URL (standard) Base64 encoding
        }
        if (get) {
            if (debugbuf != null) {
                debugbuf.append("GET " + url + " → ");
            }
        } else if (!get) {
            if (debugbuf != null) {
                debugbuf.append("POST " + url + " " + data + " → ");
            }
            if (data.length() > 0) {
                con.getOutputStream().write(data.getBytes("UTF-8"));
            }
            con.getOutputStream().close();
        }
        InputStream in = null;
        IOException ioe = null;
        try {
            in = con.getInputStream();
        } catch (IOException e) {
            in = con.getErrorStream();
            ioe = e;
        }
        try {
            byte[] buf = new byte[DATASIZE];
            int len = 0, l;
            while (len < buf.length && (l=in.read(buf, len, buf.length - len)) >= 0) {
                len += l;
            }
            if (len == buf.length) {
                throw new IllegalStateException("Reply too large");
            }
            String text = new String(buf, 0, len, StandardCharsets.UTF_8);
            if (debugbuf != null) {
                debugbuf.append(con.getResponseCode());
                debugbuf.append(" ");
                debugbuf.append(text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r"));
                debug(debugbuf.toString());
            }
            @SuppressWarnings("unchecked") Map<String,Object> out = (Map<String,Object>)parseJson(CharBuffer.wrap(text));
            out.put(null, con.getResponseCode());
            out.put(STRING_NOW, System.currentTimeMillis() / 1000);
            return out;
        } catch (Exception e) {
            if (ioe == null) {
                throw ioe;
            } else {
                throw e;
            }
        } finally {
            if (in != null) { try { in.close(); } catch (Exception e) {} }
            con.disconnect();
        }
    }

    /**
     * Send a "response_type: code" to the authorization server, opening
     * a web-server for the redirect uri.
     * Return a Map with "code", possibly "code_verifier", "iss"
     */
    private Map<String,Object> sendAuthorizationCode(String client_id) throws IOException {
        String auth_uri = getString(props, "authorization_endpoint", null);
        if (auth_uri == null) {
            throw new IllegalArgumentException("Missing \"authorization_endpoint\" property");
        }
        if (redirectHandler == null) {
            throw new IllegalStateException("RedirectURLHandler required but not set");
        }
        String codeVerifier = null;
        String state = null;

        Map<String,Object> m = new LinkedHashMap<String,Object>();
        m.put("response_type", "code");
        m.put("client_id", client_id);
        m.put("scope", getString(props, "scope", null));
        m.put("redirect_uri", getString(props, "redirect_uri", null));
        if (getBoolean(props, "state", true)) {
            state = randomString(64);
            m.put("state", state);
        }
        String ccm = getString(props, "code_challenge_method", null);
        if ("plain".equalsIgnoreCase(ccm)) {
            m.put("code_challenge", codeVerifier = randomString(64));
        } else if ("S256".equalsIgnoreCase(ccm)) {
            codeVerifier = randomString(64);
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                m.put("code_challenge", Base64.getUrlEncoder().encodeToString(digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8))));
                m.put("code_challenge_method", "S256");
            } catch (NoSuchAlgorithmException e2) {
                throw new RuntimeException(e2);
            }
        } else if (ccm != null) {
            throw new RuntimeException("Unsupported code_challenge_method \"" + ccm + "\"");
        }
        String prefix = "protocol.auth.";
        for (Map.Entry<String,Object> e : props.entrySet()) {
            if (e.getKey().startsWith(prefix) && e.getValue() != null) {
                String key = e.getKey().substring(prefix.length());
                m.put(key, e.getValue());
            }
        }

        auth_uri = auth_uri + "?" + encodeURL(m);
        Map<String,Object> response = redirectHandler.handleRedirect(this, auth_uri);
        if (getString(response, "code", null) == null) {
            throw new IOException("Request to \"" + auth_uri + "\": missing \"code\"");
        }
        if (state != null) {
            String rstate = getString(response, "state", null);
            if (rstate == null) {
                throw new IOException("Request to \"" + auth_uri + "\": missing \"state\"");
            } else if (!state.equals(rstate)) {
                throw new IOException("Request to \"" + auth_uri + "\": mismatched \"state\" " + rstate);
            }
            response.remove("state");
        }
        if (codeVerifier != null) {
            response.put("code_verifier", codeVerifier);
        }
        response.put(STRING_NOW, System.currentTimeMillis() / 1000);
        return response;
    }

    /**
     * A quick single-method JSON parser, intended to parse input which is expected to be valid.
     * Does not exacly match the JSON parsing rules for numbers.
     */
    private static Object parseJson(CharBuffer in) {
        int tell = in.position();
        try {
            char c;
            while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t') {
                tell++;
            }
            Object out;
            if (c == '{') {
                Map<String,Object> m = new LinkedHashMap<String,Object>();
                while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                if (c != '}') {
                    in.position(in.position() - 1);
                    do {
                        String key = (String)parseJson(in);
                        while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                        if (c == ':') {
                            m.put((String)key, parseJson(in));
                            tell = in.position();
                        } else {
                            throw new UnsupportedOperationException("expecting colon");
                        }
                        while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                        if (c != ',' && c != '}') {
                            throw new UnsupportedOperationException("expecting comma or end-map");
                        }
                    } while (c != '}');
                }
                out = m;
            } else if (c == '[') {
                List<Object> l = new ArrayList<Object>();
                while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                if (c != ']') {
                    in.position(in.position() - 1);
                    do {
                        l.add(parseJson(in));
                        tell = in.position();
                        while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                        if (c != ',' && c != ']') {
                            throw new UnsupportedOperationException("expecting comma or end-list");
                        }
                    } while (c != ']');
                }
                out = l;
            } else if (c == '"') {
                StringBuilder sb = new StringBuilder();
                while ((c=in.get()) != '"') {
                    if (c == '\\') {
                        c = in.get();
                        switch (c) {
                            case 'n': c = '\n'; break;
                            case 'r': c = '\r'; break;
                            case 't': c = '\t'; break;
                            case 'b': c = '\b'; break;
                            case 'f': c = '\f'; break;
                            case 'u': c = (char)Integer.parseInt(in.subSequence(0, 4).toString(), 16); in.position(in.position() + 4); break;
                        }
                    }
                    sb.append(c);
                }
                out = sb.toString();
            } else if (c == 't' && in.get() == 'r' && in.get() == 'u' && in.get() == 'e') {
                out = Boolean.TRUE;
            } else if (c == 'f' && in.get() == 'a' && in.get() == 'l' && in.get() == 's' && in.get() == 'e') {
                out = Boolean.FALSE;
            } else if (c == 'n' && in.get() == 'u' && in.get() == 'l' && in.get() == 'l') {
                out = null;
            } else if (c == '-' || (c >= '0' && c <= '9')) {
                StringBuilder sb = new StringBuilder();
                sb.append(c);
                while (in.hasRemaining()) {
                    if ((c=in.get()) == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9')) {
                        sb.append(c);
                    } else {
                        in.position(in.position() - 1);
                        break;
                    }
                }
                String s = sb.toString();
                try {
                    Long l = Long.parseLong(s);
                    if (l.longValue() == l.intValue()) {        // This can't be done with a ternary due to unboxing confusion
                        out = Integer.valueOf(l.intValue());
                    } else {
                        out = l;
                    }
                } catch (Exception e) {
                    try {
                        out = Double.parseDouble(s);
                    } catch (Exception e2) {
                        throw new UnsupportedOperationException("invalid number: " + s);
                    }
                }
            } else {
                throw new UnsupportedOperationException("invalid " + (c >= ' ' && c < 0x80 ? "'" + ((char)c) + "'" : "U+" + Integer.toHexString(c)));
            }
            return out;
        } catch (BufferUnderflowException e) {
            throw (IllegalArgumentException)new IllegalArgumentException("Parse failed: unexpected EOF").initCause(e);
        } catch (ClassCastException e) {
            in.position(tell);
            throw new IllegalArgumentException("Parse failed at " + in.position() + ": expected string");
        } catch (UnsupportedOperationException e) {
            in.position(tell);
            throw new IllegalArgumentException("Parse failed at " + in.position() + ": " + e.getMessage());
        }
    }

    /**
     * The interface required for an OAuth2 "authorization" flow that requires a callback from the server
     */
    public static interface RedirectURLHandler {
        /**
         * Initialize a callback, which will require the user to open a web-browser to continue OAuth2 authorization
         */
        public Map<String,Object> handleRedirect(OAuth2 auth, String url) throws IOException;
    }

    /**
     * An implementation of {@link RedirectURLHandler}.
     * It uses the <Code>com.sun.net.httpserver</code> package to create a local webserver
     * and then directs the user to that URL to begin the authentication process.
     */
    public static class SimpleRedirectURLHandler implements RedirectURLHandler {

        private InternalRedirectHandler wrapped;
        private SSLContext ssl;

        /**
         * Create a new SimpleRedirectURLHandler which will listen on HTTPS if the OAuth2 server its used with has an SSLContext, or HTTP otherwise 
         */
        public SimpleRedirectURLHandler() {
            this(null);
        }

        /**
         * Create a new SimpleRedirectURLHandler that will use the specified SSLContext to create an HTTPS listener
         * @param ssl the SSL context
         */
        public SimpleRedirectURLHandler(SSLContext ssl) {
            this.ssl = ssl;
        }

        @Override public Map<String,Object> handleRedirect(OAuth2 oauth2, String uri) throws IOException {
            synchronized(this) {
                if (wrapped != null) {
                    throw new IllegalStateException("SimpleRedirectURLHandler already processing another request");
                } else {
                    wrapped = new InternalRedirectHandler(ssl != null ? null : oauth2.getSSLContext());
                }
            }
            Map<String,Object> out = wrapped.handleRedirect(oauth2, uri);
            synchronized(this) {
                wrapped = null;
            }
            return out;
        }
    }

    /**
     * This is in a separate class from OAuth2.RedirectURLHandler because it accesses the com.sun.net.httpserver module, which is not
     * enabled by default in (eg) keytool. This allows the SimpleRedirectURLHandler to work without that module if it only needs to
     * do things like confirm an existing access_token or refresh_token, only loading this class if a new token is required
     */
    private static final class InternalRedirectHandler implements RedirectURLHandler {
        private com.sun.net.httpserver.HttpServer httpserver;
        private com.sun.net.httpserver.HttpContext ctx0, ctx1;
        private SSLContext ssl;

        InternalRedirectHandler(SSLContext ssl) {
            this.ssl = ssl;
        }

        @Override public Map<String,Object> handleRedirect(final OAuth2 oauth2, final String auth_uri) throws IOException {
            Map<String,Object> props = oauth2.getProperties();
            int port = getInt(props, "port", 0);
            String hostname = getString(props, "hostname", "localhost");
            String redirectPath = getString(props, "redirect_path", null);
            String initialPath = getString(props, "initial_path", null);
            if (port == 0 || redirectPath == null || initialPath == null) {
                final String redirect_uri = getString(props, "redirect_uri", null);
                try {
                    URI uri = new URI(redirect_uri);
                    if (port == 0) {
                        port = uri.getPort();
                    }
                    if (redirectPath == null) {
                        redirectPath = uri.getPath();
                    }
                    if (initialPath == null) {
                        initialPath = redirectPath.equals("/authorize") ? "/" : "/authorize";
                    }
                } catch (Exception e) {}
                if (redirectPath == null) {
                    throw new IllegalStateException("Missing \"redirect_path\" and \"redirect_uri\" properties");
                }
            }
            if (initialPath == null || initialPath.equals(redirectPath)) {
                initialPath = redirectPath.equals("/authorize") ? "/" : "/authorize";
            }

            if (ssl != null) {
                httpserver = com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress(port), 0);
                ((com.sun.net.httpserver.HttpsServer)httpserver).setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(ssl) {
                    public void configure(com.sun.net.httpserver.HttpsParameters params) {
                        params.setNeedClientAuth(false);
                        params.setSSLParameters(ssl.getDefaultSSLParameters());
                    }
                });
            } else {
                httpserver = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(port), 0);
            }

            final Map<String,Object> output = new LinkedHashMap<String,Object>();
            ctx0 = httpserver.createContext(initialPath, new com.sun.net.httpserver.HttpHandler() {
                @Override public void handle(com.sun.net.httpserver.HttpExchange t) throws IOException {
                    try {
                        if (oauth2.debug) oauth2.debug("RedirectURI TX " + auth_uri);
                        t.getResponseHeaders().add("Location", auth_uri);
                        t.sendResponseHeaders(302, -1);
                        t.close();
                    } catch (Exception e) {
                        oauth2.log(e);
                    }
                }
            });
            ctx1 = httpserver.createContext(redirectPath, new com.sun.net.httpserver.HttpHandler() {
                @Override public void handle(com.sun.net.httpserver.HttpExchange t) throws IOException {
                    try {
                        if (oauth2.debug) oauth2.debug("RedirectURI RX: " + t.getRequestURI());
                        t.getResponseHeaders().add("Location", getString(props, "final_uri", "about:blank"));
                        t.sendResponseHeaders(302, -1);
                        t.close();
                        synchronized(output) {
                            for (String s : t.getRequestURI().getQuery().split("&")) {
                                int i = s.indexOf("=");
                                String key = i >= 0 ? URLDecoder.decode(s.substring(0, i), StandardCharsets.UTF_8) : s;
                                String value = i >= 0 && i + 1 < s.length() ? URLDecoder.decode(s.substring(i + 1), StandardCharsets.UTF_8) : null;
                                output.put(key, value);
                            }
                            output.notifyAll();
                        }
                    } catch (Exception e) {
                        oauth2.log(e);
                        synchronized(output) {
                            output.notifyAll();
                        }
                    }
                }
            });
            String initialurl = (ssl != null ? "https://" : "http://") + hostname + ":" + port + initialPath;
            Thread thread = new Thread() {
                public void run() {
                    httpserver.start();
                }
            };
            thread.setDaemon(true);
            thread.setName("BFO-Publisher-OAuth2-SimpleOAuth2Callback");
            thread.start();
            oauth2.notifyURL(initialurl, null);
            synchronized(output) {
                try {
                    output.wait(oauth2.getTransactionTimeout());
                } catch (InterruptedException e) {}
            }
            httpserver.stop(1);
            httpserver = null;
            ctx0 = ctx1 = null;
            return output;
        }
    }

    /*
    public static void main(String[] args) throws Exception {
        OAuth2 oauth2 = new OAuth2();
        oauth2.setRedirectURLHandler(new OAuth2.SimpleRedirectURLHandler());
        oauth2.setCallbackHandler(new com.sun.security.auth.callback.TextCallbackHandler());
        Map<String,Object> props = new HashMap<String,Object>();
        props.put("debug", "true");
        props.put("flow", "client credentials");
        String client_id = ...;
        String client_secret = ...;
        props.put("discovery_uri", "https://accounts.google.com/.well-known/openid-configuration");
        props.put("client_id", client_id);
        props.put("client_secret", client_secret);
        props.put("scope", "openid");
        oauth2.setProperties(props);
        System.out.println(oauth2.getAuthorization());
    }
    */

}
