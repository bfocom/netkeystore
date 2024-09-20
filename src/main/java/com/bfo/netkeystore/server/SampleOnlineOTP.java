package com.bfo.netkeystore.server;

import java.security.Principal;
import java.security.PrivateKey;
import com.bfo.json.*;
import com.sun.net.httpserver.*;
import java.util.*;
import java.io.*;

/**
 * A simple Online OTP KeyAuthorization which could be used as the basis for a useful
 * implementation just by overriding the "notify" method.
 * Accepts the following parameters in the config file
 * <ul>
 *  <li><b>expiry</b> - expiry time of OTP in seconds (default is 30)</li>
 *  <li><b>otplength</b> - number of digits in OTP (default is 6)</li>
 *  <li><b>maxsessions</b> - max number of simultaneous OTPs by a principal for a single credential (default is 8)</li>
 * </ul>
 */
public class SampleOnlineOTP implements KeyAuthorization {

    private static final int EXPIRY = 30;
    private static final int OTPLENGTH = 6;

    // If the exact same Principal is used to request multiple OTPs for the same CID, any of them
    // will be considered valid - a hacker could theoretically request millions of OTPs, then
    // supply any value in the hope it's going to be a hit. So set a max number of simultaneous
    // open requests for an individual [principal,cid] combination. A value of 1 means requesing
    // a new OTP invalidates any previous one.
    private static final int MAXSESSIONS = 8;

    private Server server;
    private int expiry = EXPIRY, otplength = OTPLENGTH, maxsessions = MAXSESSIONS;
    private List<OTP> all = new ArrayList<OTP>();

    public void setServer(Server server) {
        this.server = server;
    }

    public boolean isOTP() {
        return true;
    }

    @Override public void setKeyInfo(Principal principal, Credential credential, String cid, Json info) {
        Json otp = Json.read("{}");
        info.put("OTP", otp);
        otp.put("presence", "true");
        otp.put("type", "online");
        otp.put("format", "A");
    }

    @Override public PrivateKey getPrivateKey(Principal principal, Credential credential, String cid, Json req) {
        // Note if the exact same Principal is used to request multiple OTPs for the same CID, any of them
        // will be considered valid. That's how it has to be.
        String password = req.stringValue("OTP");
        synchronized(all) {
            for (int i=0;i<all.size();i++) {
                OTP otp = all.get(i);
                if (otp.expiry < System.currentTimeMillis()) {
                    all.remove(i--);
                } else if (otp.principal.equals(principal) && otp.credential.equals(credential) && otp.value.equals(password)) {
                    PrivateKey key = credential.getPrivateKey(null);
                    if (key == null) {
                        throw new IllegalStateException("Local password not specified for cid=\"" + cid + "\"");
                    }
                    return key;
                }
            }
        }
        return null;
    }

    @Override public void configure(Json config) throws Exception {
        if (config.isNumber("expiry")) {
            expiry = config.numberValue("expiry").intValue();
            if (expiry < 1 || expiry > 600) {
                expiry = EXPIRY;
            }
        }
        if (config.isNumber("length")) {
            otplength = config.numberValue("length").intValue();
            if (otplength < 1 || otplength > 10) {
                otplength = 6;
            }
        }
        if (config.isNumber("maxsessions")) {
            maxsessions = config.numberValue("maxsessions").intValue();
            if (maxsessions < 1 || maxsessions > 1000) {
                maxsessions = MAXSESSIONS;
            }
        }
    }

    @Override public void initialize(HttpServer htserver, String prefix, Json info) {
        info.get("methods").put(info.get("methods").size(), "credentials/sendOTP");
        htserver.createContext(prefix + "credentials/sendOTP", new CredentialsSendOTPHandler());
    }

    /**
     * Generate and store an OTP
     * @param principal the principal
     * @param credential the credential
     * @return the OTP
     */
    protected String generateOTP(Principal principal, Credential credential, String cid) {
        char[] c = new char[otplength];
        for (int i=0;i<c.length;i++) {
            c[i] = (char)('0' + server.getRandom().nextInt(10));
        }
        String value = new String(c);
        synchronized(all) {
            int count = 0;
            for (int i=0;i<all.size();i++) {
                OTP otp = all.get(i);
                if (otp.expiry < System.currentTimeMillis()) {
                    all.remove(i--);
                } else if (otp.principal.equals(principal) && otp.cid.equals(cid) && ++count > maxsessions) {
                    all.remove(i--);
                }
            }
            OTP otp = new OTP(principal, credential, cid, System.currentTimeMillis() + expiry * 1000, value);
            all.add(otp);
        }
        return value;
    }

    /**
     * Notify the user that a new OTP has been generated, by printing a message to the console.
     * @param principal the principal
     * @param credential the credential
     * @param otp the OTP
     */
    protected void notifyOTP(Principal principal, Credential credential, String cid, String otp) {
        Object id = principal instanceof JWT ? ((JWT)principal).getPayload() : principal;
        System.out.println("* New OTP for user="+id+" key="+cid+": OTP=\"" + otp + "\"");
    }

    private static class OTP {
        final Principal principal;
        final Credential credential;
        final String cid, value;
        final long expiry;
        OTP(Principal principal, Credential credential, String cid, long expiry, String value) {
            this.principal = principal;
            this.credential = credential;
            this.cid = cid;
            this.expiry = expiry;
            this.value = value;
        }
    }

    private class CredentialsSendOTPHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Json req = server.receive(exchange);
                if (req != null) {
                    Principal principal = server.getAuthorization().authorize(exchange);
                    if (principal != null) {
                        if (!req.isString("credentialID")) {
                            server.send(exchange, 400, server.createError("invalid_request", "Missing (or invalid type) string parameter credentialID", null), null);
                        } else {
                            final String cid = req.stringValue("credentialID");
                            final Credential credential = server.getCredentials().getCredential(principal, cid);
                            if (cid == null) {
                                server.send(exchange, 400, server.createError("invalid_request", "Invalid parameter credentialID", null), null);
                            } else {
                                notifyOTP(principal, credential, cid, generateOTP(principal, credential, cid));
                                server.send(exchange, 201, null, null);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


}
