# hsmshare
![test](https://raw.githubusercontent.com/faceless2/netkeystore/main/aux/arrow.svg)

This project is an attempt to reconcile a problem in software development: development is becoming *more distributed*,
with VMs, cloud based builds and distributed teams, while attestation is becoming *more localised* due to a requirement that
HSM (hardware security modules) are used to store keys for signing software.

Network HSM devices are available but they are expensive, and presume you have somewhere to put them.
USB HSMs like the Yubikey range are cheap, but need to be connected to a USB port on the machine doing the signing.

This project has three aspects:

* a server component which runs on the computer with the USB HSM, listening for signing requests
* a client component which simulates a locally connected Key Store, but actually relays all operations to the server
* the network protocol they communicate with, which is a trivial - stateless CBOR-over-HTTP, with service discovery using zeroconf.

Zeroconf in this case really does mean zero configuration for the client: it will find any servers on the network automatically,
and combine all their shared keys into one KeyStore.

The server is written in Java and is tested with Yubikey FIPS 5 tokens, but should with with any PKCS#11 based HSM
that can be used with Java. The client is also Java, a `java.security.Provider` providing a `java.security.KeyStore`
for use with signing.

Several example configurations are shown in the `examples` folder. To start a server

```shell
# Start a server
$ java -jar netkeystore-1.0.jar --config examples/server-sample.yaml
```

And to list keys with "keystore" and sign a Jar with `jarsigner`
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
