# Net KeyStore
Java Client and Server for creating remote digital signatures. Supports the network API from the [Cloud Signature Consortium](https://cloudsignatureconsortium.org)

Development is becoming **more distributed** as attestation is becoming **more localized**, due 
to a requirement that HSM (hardware security modules) are used to store keys for signing software. The two solutions to this are 
either manage your own Network HSM device, or outsource this to one of many Cloud-based signature providers.

This project provides solutions for both approaches:
* A Java KeyStore that connects to Network Signing Services
* A Java server that turns a local Keystore (software or PKCS#11) into a Network Signing Service.

Tested, working and used daily by [BFO](https://bfo.com) to sign Jars on a server in one location with USB-based HSM in another.


## Client Component
The `com.bfo.netkeystore.client` package is a standard `java.util.KeyStore` that wraps one or more network-based signature providers.
The current implementation supports the API from the https://cloudsignatureconsortium.org (v1.0.4), but other protocols can be added.
It can be used anywhere a regular `java.util.KeyStore` is used for signing, so usage is trivial:

```java
Provider provider = new NetProvider();
provider.load(new FileInputStream("config.yaml"));
KeyStore keystore = KeyStore.getInstance(NetProvider.KEYSTORE_TYPE, provider);
keystore.load(null, password);
// it's a regular java.security.KeyStore. Get the keys from it and sign as normal.
```

Features:
* Single Jar with no dependencies except Java 8 or later
* Cloud Signature Consortium API implementation (API v1)
  * supports "external", "TLS", "basic", "oauth2code" and "oauth2client" user authorization
  * supports key authorization by explicit or implicit PIN and both online and offline OTP
* Supports finding servers over Zeroconf, for no-configuration setup if the Server component is running on the network
* Works with keytool and jarsigner

See the `example/TestClient.java` for a full example, and `example/client-sample.yaml` for a documented configuration file.


## Server Component
The `com.bfo.netkeystore.server` package is a standalone webserver which implements
a Cloud Signature Consortium RSSP (remoter signing service provider). It will wrap any `java.util.KeyStore`, and has been tested with
file-based keystores (PKCS#12 and JKS) as well as hardware based PKCS#11 tokens (a USB Yubikey, containing a code-signing certificate).

Features:
* Single Jar with no dependencies except Java 8 or later
* Cloud Signature Consortium API implementation (API v1)
  * Supports "external", "basic" and "oauth2" authorization (which proxies to a third-party OAuth2 provider)
  * Server supports HTTP and HTTPS
  * JWT based tokens
  * EC and RSA keys
  * Explicit, implicit passwords supported. OTP passwords supported, with a sample implementation.
  * Designed for extension and to accommodate CSC API v2
* Supports announcing service over Zeroconf, for no-configuration setup with compatible clients.


## Building and testing

There are two dependencies:
[JSON](https://faceless2.github.io/json) and [Zeroconf](https://faceless2.github.io/zeroconf) libraries,
both written by BFO, included in the "lib" folder and will be built into the generated Jars. Building is as simple as running `ant`. Two Jars
are created:
* `netkeystore-client-2.0.jar` contains the Provider for use as a Java KeyStore
* `netkeystore-server-2.0.jar` contains a Main class which starts a web-server and acts as the server implementation.

The current release can be downloaded from 
[netkeystore-client-2.0.jar](https://bfocom.github.io/netkeystore/dist/netkeystore-client-2.0.jar) and
[netkeystore-server-2.0.jar](https://bfocom.github.io/netkeystore/dist/netkeystore-client-2.0.jar), and here is the
[javadoc](https://bfocom.github.io/netkeystore/docs).

Several example configurations are shown in the `example` folder. To start a server

```shell
# Start a server
$ ant build
$ cd example
$ java -jar ../dist/netkeystore-server-2.0.jar --config server-sample.yaml
```

Alternatively double-click the Jar for a simple GUI: the key icon in the system tray will load configurations
and start/stop the server.

To sign a byte array programatically, using an client auto-configured with Zeroconf:

```java
import new com.bfo.netkeystore.client.NetProvider;
import java.security.*;

Provider provider = new NetProvider();
KeyStore keystore = KeyStore.getInstance(NetProvider.KEYSTORE_TYPE, provider);
keystore.load(null, password);
PrivateKey privkey = (PrivateKey)keystore.getKey(alias, password);
Signature sig = Signature.getInstance(alg, provider);
sig.initSign(privkey);
sig.update(data);
byte[] sigbytes = sig.sign();
```

To sign a PDF with the [BFO PDF Library](https://bfo.com/products/pdf) using a configuration from a file
```java
import com.bfo.netkeystore.client.NetProvider;
import java.security.*;
import java.io.*;
import org.faceless.pdf2.*;

Provider provider = new NetProvider();
provider.load(new FileInputStream("config.yaml"));
KeyStore keystore = KeyStore.getInstance(NetProvider.KEYSTORE_TYPE, provider);
keystore.load(null, password);
PDF pdf = new PDF(new PDFReader(new FileInputStream("input.pdf")));
FormSignature sig = new FormSignature();
SignatureHandlerFactory sigfactory = new AcrobatSignatureHandlerFactory();
sig.sign(keystore, alias, password, sigfactory);
pdf.getForm().getElements().put("Sig", sig);
pdf.render(new FileOutputStream("signed.pdf"));
```

A more complete example is in the "example" folder, but the main advantage it has over these
code snippets is it uses a `Keystore.CallbackHandlerProtection` for authorization rather than
a `char[] password`. This necessary for OAuth2 authorization (as a Callback is used to notify
the client of the URL to be opened for authorization) and recommended if there is more than
one server in the configuration.

To list keys with `keytool`
```shell
# Java 8+
$ keytool -J-cp -Jnetkeystore-client-2.0.jar \
     -providerClass com.bfo.netkeystore.client.NetProvider \
     -providerarg path/to/config.yaml \
     -keystore NONE -storetype NetKeyStore -list -v

# Java 9+
$ keytool -providerPath netkeystore-client-2.0.jar \
     -providerClass com.bfo.netkeystore.client.NetProvider \
     -providerarg path/to/config.yaml \
     -keystore NONE -storetype NetKeyStore -list -v
```

To sign jars with `jarsigner`
```
$ jarsigner -J-cp -Jnetkeystore-client-2.0.jar \
     -providerClass com.bfo.netkeystore.client.NetProvider \
     -providerarg path/to/config.yaml \
     -keystore NONE -storetype NetKeyStore myfile.jar "myalias"
```

For those still using Apache Ant to build, the `<signjar>` task which calls `jarsigner` cab be used as shown here
```xml
<signjar jar="${jar}" alias="${alias}" digestalg="SHA-256" storepass="password"
     storetype="NetKeyStore" keystore="NONE"
     providerclass="com.bfo.netkeystore.client.NetProvider" providerarg="path/to/config.yaml">
  <arg value="-J-cp"/>
  <arg value="-J${buildlib}/netkeystore-1.0.jar"/>
</signjar>
```

In both cases the store password is the password to log into the service, and the key password is the password or OTP
to unlock the key. If not using a configuration file, the `providerarg` can be omitted.

For Java 9+ when using a OAuth2 authentication, the additional parameters `-J--add-modules -Jjdk.httpserver`
may be required. This will only be the case where no previous authorization has been made.

## Sample Client Configuration

```yaml
# A sample configuration file for the NetKeyStore client.
# Client configuration is optional! If no configuration is specified
# it will default to searching for servers using Zeroconf
 
#zeroconf: true               # Listen for servers shared over Zeroconf? (default: true)
#debug: true                  # Log network traffic to System.out? (default: false)
#base: "/path/to/this/file"   # The optional absolute path to resolve any relative paths in this file

# The "authorizations" section details where to store temporary authorizations like
# access tokens. This section is optional, and all keys within it are also optional.
# If no file is specified they will be saved in Java preferences,
# If no password is specified, wherever they are saved they will be unencrypted.
authorizations:
  keystore: "authorizations.json"     # filename to save authorizations
#  password: "password"               # password to encrypt authorizations


# The "servers" section defines the set signature services to connect to.
# Multiple indepdent servers can be specified. The "type" property is required
# for each (the only current value is "csc"). Other properties very by type.
#
# If "Zeroconf" is true servers may be added to this list dynamically.
#
servers:

  example:
    type: "csc"                                 # Cloud Signature Consortium API
    disabled: true                              # Set disabled=true to disable a server temporarily
    url: "https://cs-try.ssl.com/csc/v0"        # URL to connect to (required).
#    timeout: 15                                 # timeout (in seconds) for network operations (default: 15)

    client:
      keystore: "keystore.pkcs12"               # For HTTPS servers, the keystore to load the trusted certificates
      password: "password"                      # from. If "password" is set it may also contain client certificates.
#      keystore: "insecure"                      # The special value "insecure" will accept any server certificates.

    basic:                                      # If the server uses "basic" authorization:
      username: "username"                      #   "username" should be set, or it will be requested via a NameCallback
      password: "password"                      #   "password" may be set, or the keystore password is used.

    oauth2:                                     # If the server uses "oauth2" authorization:
      client_id: "username"                     #   "client_id" should be set, or will be requested via a NameCallback
      client_secret: "password"                 #   "client_secret" may be set, or the keystore password is used
      redirect_uri: "https://localhost:9870/"   #   "redirect_uri" key is required.
#      final_uri: "https://bfo.com"             #   (optional) "final_uri" is the url to end on after authorization
#      flow: "authorization"                    #   (optional) "flow" can be "authorization" (the default) or "client credentials"
#      state: false                             #   (optional) "state" is sent by default, but set this to false to disable.
#      code_challenge_method: "S256"            #   (optional) "code_challenge_method" can be plain or S256 to use this protocol
#      scope: "service"                         #   (optional) "scope" defaults to "service" but can be overridden

      # OAuth2 is, of course, complicated. More options, including the ability to send non-standard properties, are
      # described in the javadoc for OAuth2.java. User a CallbackHandler rather than char[] password for OAuth2

      redirect_server:
        keystore: "keystore.pkcs12"             #    If the oauth2 redirect_server must be HTTPS, this section specifies the
        password: "password"                    #    "keystore" and "password" containing the server SSL certificates.

# The "aliases" section specifies optional aliases for keys, changing the
# typically long names given by servers to shorter values in the local KeyStore.
# Be warned, some implentations will change the alias of a key for different login session.
aliases:
  mykey: "example/780f0eea-7123-4084-bcc0-123456789abc"
```

### Sample Server Configuration
```yaml
# A sample configuration file for the NetKeyStore server.

name: "MyKeyServer"         # The name of the server (required)
zeroconf: true              # Announce server over zeroconf? (default: true)
#debug: true                # Log network traffic to System.out? (default: false)
#base: "path/to/this/file"  # The optional base against which to resolve any relative paths in this file
port: 18001                 # The port to run the webserver on (default: 0, to auto-select)
#version: "1.0.3"           # The version number to claim to support (default: "1.0.3")
#max_input_buf: 8192        # The maximum number of bytes in a client request (default: 8192)
#prefix: "/prefix/"         # The prefix for the URLs served by this server (default: none)
#url: "http://blah.com"     # The URL to use when announcing this server on zeroconf (default: derived automatically)
#static: "path/to/static"   # The path from which to serve static files if the URL doesn't match anything else (default: none)

# The optional "info" map can specify any other properties that need to be reported on the "info" URL.
info:
  description: "An example CSC server"

# The "key_auth" section is optional, and determines how passwords for individual keys are unlocked.
# If unset the client must supply the password (or share_password, see below), but if not the "type"
# property must be a classname of an instanceof of KeyAuthorizationHandler, with any other properties
# passed to that classes "configure" method. Alternatively the value "explicit" can be used to 
# simply use the local_password (see below) for each key 
key_auth:
#  type: implicit                 # use the "local_password" field set on each key
  type: explicit                 # the default: ask the client for the password
#  type: com.bfo.netkeystore.server.SampleOnlineOTP   # class name of an implementation


# The "https" section is optional. If specified the server will serve over HTTPS not HTTP.
# It needs a KeyStore containing the HTTPS key and certificates - any keystore will do,
# it's specified the same way as in the "shares" section.
#https:
#  type: "pkcs12"
#  path: "example-keystore.pkcs12"
#  password: "password"


# The "auth" section determines how a client authenticates with this server.
# This section is required; the "type" property specifies the method.
auth:
  # "open" authentication has no extra properties. No authentication is performed
  type: open

  # "basic" authentication requires a username/password from the client to login.
  # The users are listed in the config file - each needs a "name" and password,
  # currently specifiable as "plaintext" only. They may optionally have a list
  # of credentials which determine which keys they can use; if unspecified, they
  # can access all keys.
#  type: basic
#  users:
#    -  { name: "user1", plaintext: "password" }
#    -  { name: "user2", plaintext: "password" }

   # "oauth2" authentication uses a third-party server to to the authentication.
   # The access_token is then passed into this server, were it is verified with
   # the "verify_url" using the token introspection protocol (RFC7662) - the
   # token can also be substituted into the query string if it contains {TOKEN}
   #
   # The "oauth2" server can be used to specify an oauth2 server that matches
   # the path requirements for CSC signatures, or the "auth_url" and "token_url"
   # can be specified to have this server proxy oauth2/authorize and oauth2/token
   # to those URLs.
   #
   # The commented out example here would use Google OAuth2 as an authorization
   # server - this won't work as it doesn't provide a "server" scope, but shows
   # how it could be done.
#  type: oauth2
#  auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
#  token_url: "https://www.googleapis.com/oauth2/v4/token"
#  verify_url: "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={TOKEN}"
#  scope: "service openid"     # CSC requires "service", but it can be changed here. "*" is wildcard for testing



# The "shares" section describes the keystores that are shared. Multiple keystores
# can be specified here, they will be presented as a single list on the network.
# Each key will be prefixed with the keystore name plus a "/", but the "aliases"
# section below can adjust this.
shares:

  sample:
    type: "pkcs12"                    # File based keystores are pkcs12, jks or jceks (required)
    path: "example-keystore.pkcs12"   # the filename to load the keystore from (required)
    password: "password"              # the password to open the store (required)
#    obfuscate_names: true            # if set to true, key identifiers will be replaced with something anonymous.
                                      # Primarily useful for when auth is "open" and key_auth is "implicit",
                                      # and only the "userid" passed into the list method distinguishes users.

    # The optional "keys" sub-section in a share allows properties to be set per-key.
    # In particular the "local_password" property is the password for the key, which needs to be specified
    # if you don't want the physical password to be sent over there wire: it's required when using OTP
    # or implicit passwords. If the "share_password" property is also set, then it's used as a proxy:
    # if the user enters the correct "share_password", the "local_password" is used.
    keys:
      "test-rsa-1024":
        disabled: true              # Any key can be disabled by setting "disabled" to true
      "test-rsa-2048":
        local_password: "password"  # the password for the key in the keystore
        share_password: "secret"    # the password we need the user to enter to unlock the key
      "test-ec-p521":
        users: ["user2"]            # keys can be restricted to a specific list of users

  yubikey:          
    type: "pkcs11"                    # PKCS#11 based keystores use type="pkcs11"
    disabled: true                    # Any share can be disabled by setting "disabled" to true
    library: "/usr/local/lib/libykcs11.so"  # required (as would be specified in the PKCS#11 conf file)
    password: "123456"                # the password to open the store (required)
    # slot, slotlistindex, description, enabledmechanisms, disabledmechanisms can also be specified
    
    # Use of "local_password" and "share_password" is highly recommended for PKCS#11 keystores to prevent
    # them locking a key after too many failed unlock attempts. 
    keys:
      "alias of key in keystore":
        local_password: "12346"     # the password for the key in the keystore
        share_password: "password"  # the password we need the user to enter to unlock the key



# The "aliases" section specifies optional aliases for keys, changing the
# default name they are shared by ("keystore name/key alias") to something else.
aliases:
  "mykey": "yubikey/alias of key in keystore"
```
