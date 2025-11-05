package com.bfo.netkeystore.client;

import java.util.*;
import java.net.*;
import com.bfo.json.*;
import com.bfo.zeroconf.*;

/**
 * The Zeroconf support classes. Spun out from Core to make Zeroconf optional.
 */
class ZeroconfSupport implements ZeroconfListener {

    private static final String SERVICE = "_netkeystore._tcp";
    private final Core core;
    private final Zeroconf zeroconf;

    ZeroconfSupport(Core core) {
        this.core = core;
        this.zeroconf = new Zeroconf();
        this.zeroconf.query(SERVICE, null);
        this.zeroconf.addListener(this);
    }

    @Override public void serviceNamed(String type, String name) {
        if (type.equals(SERVICE)) {
            zeroconf.query(type, name);
        }
    }

    @Override public void serviceAnnounced(Service service) {
        if (SERVICE.equals(service.getType()) && !service.getAddresses().isEmpty()) {
            InetSocketAddress address = new InetSocketAddress(service.getAddresses().iterator().next(), service.getPort());
            if ("2".equals(service.getText().get("version"))) {
                try {
                    String name = service.getName();
                    Json json = Json.read(service.getText().get("config"));
                    core.addServer(name, json, true);
                } catch (Exception e) {
                    if (core.isDebug("zerconf")) {
                        core.warning("Zeroconf Server failed to configure", e);
                    }
                }
            }
        }
    }

    @Override public void serviceExpired(Service service) {
        if (SERVICE.equals(service.getType())) {
            String name = service.getName();
            core.removeServer(name, true);
        }
    }

}
