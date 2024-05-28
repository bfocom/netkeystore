# hsmshare
![test](https://raw.githubusercontent.com/faceless2/netkeystore/main/aux/arrow.svg)

This project is an attempt to reconcile a problem in software development: development is becoming *more distributed*,
with VMs, cloud based builds and distributed teams, while attestation is becoming *more localized* due to a requirement that
HSM (hardware security modules) are used to store keys for signing software.

Network HSM devices are available but they are expensive, and presume you have somewhere to put them.
USB HSMs like the Yubikey range are cheap, but need to be connected to a USB port on the machine doing the signing.

This project turns a local KeyStore into a network KeyStore. It has three aspects:

* a server component which runs on the computer with the USB HSM, listening for signing requests
* a client component which simulates a locally connected Key Store, but actually relays all operations to the server
* the network protocol they communicate with, which is a trivial - stateless CBOR-over-HTTP, with service discovery using zeroconf.


The server is written in Java and is tested with Yubikey FIPS 5 tokens, but should with with any PKCS#11 based HSM
that can be used with Java (and also with software keystores like PKCS#12 files).

The client is also Java, and consists of a `java.security.Provider` providing a `java.security.KeyStore`.
Zero configuration really applies here; any servers on the network are foundautomatically and combined
into one KeyStore.

### Building and testing

There are two dependencies: JSON and Zeroconf libraries, both written by BFO and included in the "lib" folder,
so building is as simple as running `ant`. A single `netkeystore-1.0.jar` file is generated in `dist`

Several example configurations are shown in the `example` folder. To start a server

```shell
# Start a server
$ ant build
$ cd example
$ java -jar ../dist/netkeystore-1.0.jar --config server-sample.yaml
```

Alterantively double-click the `netkeystore` Jar for a simple GUI: the key icon in the system tray will load configurations
and start/stop the server.

Client use requires no configuration. To list keys with "keystore" and sign a Jar with `jarsigner`
```shell
$ keytool -J-cp -Jnetkeystore-1.0.jar -providerClass com.bfo.netkeystore.NetProvider \
    -keystore NONE -storetype NetKeyStore -list

Enter keystore password:  
Keystore type: NETKEYSTORE
Keystore provider: NetProvider

Your keystore contains 2 entries

ks1.eckey, null, PrivateKeyEntry, 
Certificate fingerprint (SHA-256): 43:BA:30:57:8A:2C:DF:87:D3:78:C5:28:CA:90:99:3E:15:FB:A4:E4:F4:0E:47:18:83:18:59:48:C7:B9:28:93
ks2.rsakey, null, PrivateKeyEntry, 
Certificate fingerprint (SHA-256): 77:10:E8:3C:E8:2A:EE:37:95:91:0F:69:03:E7:64:0E:C2:7F:68:84:36:79:A2:EC:89:E9:9B:3A:AE:BA:C6:28

$ jarsigner -J-cp -Jnetkeystore-1.0.jar -providerClass com.bfo.netkeystore.NetProvider \
     -keystore NONE -storetype NetKeyStore myfile.jar "ks1.eckey"

Enter Passphrase for keystore: 
jar signed.
```
Signing programatically is just as simple.

```java
Provider provider = new com.bfo.netkeystore.NetProvider();
KeyStore keystore = KeyStore.getInstance("NetKeyStore", provider);
keystore.load(null, password);
PrivateKey privkey = (PrivateKey)keystore.getKey(alias, password);
Signature sig = Signature.getInstance(alg, provider);
sig.initSign(privkey);
sig.update(data);
byte[] sigbytes = sig.sign();
```

For those still using Apache Ant to build, the `<signjar>` task can integrate with this as shown here
```xml
<signjar jar="${jar}" alias="${alias}" digestalg="SHA-256" storepass="password" storetype="NetKeyStore"
     keystore="NONE" providerclass="com.bfo.netkeystore.NetProvider" tsaurl="${tsaurl}">
  <arg value="-J-cp"/>
  <arg value="-J${buildlib}/netkeystore-1.0.jar"/>
</signjar>
```

## Network protocol

The network protocol is intentionally trivial, with the intent it's easy to build a client in any language.
Objects are sent as CBOR, but shown in their JSON equivalents below. Private keys are serialized as JWK format,
minus any private information (the minimum required fields are just "kty" and "x5c")


```http
POST /list-v1
Content-type: application/cbor
{
  "auth":[
    {
      "type":"password",
      "password":"secret"
    }
  ]
}


HTTP/1.1 200 OK
Content-type: application/cbor
{
  "type":"list-v1",
  "keys":{
    "ks1.eckey":{
      "kty": "EC",
      "alg": "ES256",
      "crv": "P-256",
      "x5c":["MIIB9zCCAZygAwIBAgIJAMmeEVyfIStoMAoGCCqGSM49BAMCMG8xCzAJBgNVBAYTAlpaMRAwDgYDVQQIEwdVbmtub3duMRIwEAYDVQQHEwlUZXN0dmlsbGUxEjAQBgNVBAoTCVRlc3QgQ29ycDEQMA4GA1UECxMHVW5rbm93bjEUMBIGA1UEAxMLVGVzdCBUZXN0ZXIwHhcNMjQwNTI0MTgwMzIxWhcNMzQwNTIyMTgwMzIxWjBvMQswCQYDVQQGEwJaWjEQMA4GA1UECBMHVW5rbm93bjESMBAGA1UEBxMJVGVzdHZpbGxlMRIwEAYDVQQKEwlUZXN0IENvcnAxEDAOBgNVBAsTB1Vua25vd24xFDASBgNVBAMTC1Rlc3QgVGVzdGVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPVcUCbKebWjIYKwqwqiYvk7sfBc9KbIx1CoqWoSOsvbzrnwPgJK0-m5k-2Q-WrNyTrtVNHjXEBA1u5ACpBAGpaMhMB8wHQYDVR0OBBYEFA24mgMJaN5xWNERjVL98Il3EVpLMAoGCCqGSM49BAMCA0kAMEYCIQDJqRxNZBJEfXWfcjCmWS2PcNRjNdeWEsEY_dzxYm5UvwIhAOIbbHh1siJRxgNt0wR6su0RLFlFRcBikm3Cx7cwTfG2"
     ]
   },
   "ks2.rsakey": {
     "kty": "RSA",
     "n":"AJ8p18rv4Kl2U8EUxWr5lz72HFM6KS_OyYnsJfAlL2Hm8FNN7ZLTmWpNF5CQSXSEu_ilQN-Lb3M9ZF5OT0hWJbpIldsyu1feiC1z4caWEB9s5MCQhget4jMERIThlRwYc2I0titRR1MQt3Dzmleab2v9e7vcIZrz1sMw1JPI2Q7TKveEkMf5pFHwpY6PIGIe3_zNT4PPEQJEIr5udDEksY-OUiQeSh3P4DbkmTGxFABwcA93VosUpwtzv_0QApNVANkAhNsQx7OmQ1HxLzLkXHOe7zdwVBZDzedGc4-B4gtVjzl6dwVv542jLE36bd2aKEeioXlIDzRxZC0ANE9nv5s",
     "e":"AQAB",
     "x5c":["MIIDgTCCAmmgAwIBAgIILd4t_grn9wowDQYJKoZIhvcNAQELBQAwbzELMAkGA1UEBhMCWloxEDAOBgNVBAgTB1Vua25vd24xEjAQBgNVBAcTCVRlc3R2aWxsZTESMBAGA1UEChMJVGVzdCBDb3JwMRAwDgYDVQQLEwdVbmtub3duMRQwEgYDVQQDEwtUZXN0IFRlc3RlcjAeFw0yNDA1MjQxODA0MDFaFw0zNDA1MjIxODA0MDFaMG8xCzAJBgNVBAYTAlpaMRAwDgYDVQQIEwdVbmtub3duMRIwEAYDVQQHEwlUZXN0dmlsbGUxEjAQBgNVBAoTCVRlc3QgQ29ycDEQMA4GA1UECxMHVW5rbm93bjEUMBIGA1UEAxMLVGVzdCBUZXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfKdfK7-CpdlPBFMVq-Zc-9hxTOikvzsmJ7CXwJS9h5vBTTe2S05lqTReQkEl0hLv4pUDfi29zPWReTk9IViW6SJXbMrtX3ogtc-HGlhAfbOTAkIYHreIzBESE4ZUcGHNiNLYrUUdTELdw85pXmm9r_Xu73CGa89bDMNSTyNkO0yr3hJDH-aRR8KWOjyBiHt_8zU-DzxECRCK-bnQxJLGPjlIkHkodz-A25JkxsRQAcHAPd1aLFKcLc7_9EAKTVQDZAITbEMezpkNR8S8y5Fxznu83cFQWQ83nRnOPgeILVY85encFb-eNoyxN-m3dmihHoqF5SA80cWQtADRPZ7-bAgMBAAGjITAfMB0GA1UdDgQWBBQi1SStxcO_fC-gPDCfi4LydNRNnjANBgkqhkiG9w0BAQsFAAOCAQEAPyEIi0dGPLNt52z4laj_aFbYbz2dQKNRbZzu_a5OWuuxlIYafcB1RzEqbe3lXIA4448aAneOpUUpmtlFjM_lzLm1A1F8Hs7uzhrp64TL79fwEaeGxE5-y_KgE23Pnoee8kWV-VdG-1yRxQ79pLB1rVci675qr8DJBFHniaWXZPkKv7jJpxcVT1WqlrlNoNiRrT1K62I9byZ8QRFHfzPARN1eO7SgHxfkHDb3lrXp9nsG_kNybfJN769y5sC-Wsfdtv5FS6VF2jpSXBh-mxrg3xKsJ7e9JrGymoJABssPNdSKvgeJf56molYS8YgdCKp_LJXV_30DPiZRZ3rlFOgPsg"]
    }
  }
}


POST /sign-v1
Content-type: application/cbor
{
  "key": "ks1.eckey",
  "sig_alg": "ECDSA",
  "digest_alg": "SHA256",
  "digest": "zQDiksWXDTxeLw_6UXHlVbxGv8T63ftKQYtoQLhueaM",
  "auth":[
    {
      "type": "password",
      "for": "ks1",
      "password": "secret"
    }, {
      "type": "password",
      "for": "ks1.eckey",
      "password": "secret"
    }
  ]
}

HTTP/1.1 200 OK
Content-type: application/cbor
{
  "type": "sign-v1",
  "signature": "MEQCIGLK9crNtoHSiCl4nDN-Z7F_ZdmF4uMANnGOY1a6xmOXAiBUdANsOFk5VBQqdL0MY4f9aiz2JVaAdijsqPeeOdwBXg"
}
```

Zeroconf is used to advertise the services, using the `_netkeystore._tcp` service name. The TXT record may contain
`secure=true` to state the server uses HTTPS, and a `path=/prefix` property to add a prefix for HTTP requests.

## TODO

This is a very new project, but is working as described above. Supported are all signature algorithms of the form HASHwithKEY,
where "HASH" is one of SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384 and SHA3-512 and "KEY" is "RSA" or "ECDSA".

Todo are:

* Add RSAPSS, Ed25519 and Ed448
* Config file format is a bit ad-hoc
* Proof of concept in another language would be nice
