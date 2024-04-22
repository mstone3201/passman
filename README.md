# passman

passman is a cross-platform password manager designed for private use. The backend is written in C++ and uses [asio](https://github.com/chriskohlhoff/asio) and [OpenSSL](https://www.openssl.org/), while the frontend is written in Javascript. I made this for personal use, but anyone is welcome to try it out. My main motivation for making this is that leaving your passwords in someone else's hands, such as a commercial password manager, despite the guarantees they make, can be a little scary. Most people who find that their information has been stolen are usually victims caught in the crossfire of large scale attacks on sites with a large user base, rather than a targeted attack specifically on them. Since passman is designed for private use, unless someone is targeting you in particular, no one will likely even find your passman server to begin with.

## Features

* Asynchronous HTTPS server using coroutines
* Password protected server
* Self-signed certificate generation
* Password protected user data store
* End-to-end AES-256-GCM encyption for the store
* PBKDF2 key derivation from the client password
* Server enforced store consistency
* Random password generation

## Installation

1. Make sure you have a C++ compiler, [CMake](https://cmake.org/), and [vcpkg](https://vcpkg.io/) installed.
2. Download

    ```console
    git clone https://github.com/mstone3201/passman.git
    ```

3. Build

    ```console
    cd passman
    cmake --preset release
    cmake --build --preset release
    ```

4. The executable will be located in `/build/bin/`.

## Running

Please see [Best Practices](#best-practices) before using passman.

### Server

1. Run `./passman <port>` where `<port>` is the port number for the server to run on.
2. Enter a server password. This is also the server password that the client will use.
3. If the `private_key.pem` or `certificate.pem` files are not there, you will be prompted to enter the server IP address. This is needed to create `certificate.pem`. Then, both files will be generated and the server password will be used to encrypt `private_key.pem`.
    * To change the server password, delete either file to regenerate them with the new server password.
    * `certificate.pem` is a self-signed root certificate. See [Certificate](#certificates) for more information.
4. Enter `stop` to stop the server and save the store.
    * The store is automatically saved every 5 minutes.

### Client

1. Connect to `https://<ip>:<port>` with a web browser.
2. Enter the server password in the corresponding textbox.
3. Enter a client password in the corresponding textbox.
4. Click the Load button to retrieve the store from the server and unencrypt it with the client password.
5. Edit the store.
6. Click the Commit button to encrypt the store using the client password and send it to the server.
    * To change the client password, first load it using the old client password, then enter the new client password and commit the store.
    * When making a commit, the client must prove to the server that it knows the state of the store on the server. If two clients are committing to the store at the same time, one of them will be successful and the other will fail. The client that failed will need to load the store again to get the latest version of the store.

### Password Generation

Passwords are generated by randomly selecting a character from each group `count` number of times and shuffling them together. A secure randomly generated password should have a high number of combinations. For reference, the default group has `2.4e62` combinations with a count of `32`. Generally, the length of the password should be increased to improve the strength of the password rather than adding extra characters to a group. Groups should be used to guarantee that a generated password includes certain characters, for instance a site which requires a password to have an upper case letter, a numeric value, and an _.

## Security Overview

Before outlining the security model that passman uses, I want to mention that I am not a security expert even in the slightest. The few security courses I took in college do not make me qualified to comment on what security guarantees passman makes. However, I will describe what security guarantees I *think* passman makes.

### Model

All communications between the client and the server are made through TLS 1.3. TLS guarantees confidentiality, integrity, and authenticity. This means that no one other than the client and the server can know what was sent, the data cannot be manipulated, and the client knows for sure that it is talking to the legitimate server (see [Certificates](#certificates)). The server private and public keys are generated using OpenSSL 3 and encrypted using the server password when saved on disk. The store is encrypted on the client side using AES-256-GCM encryption before being sent to the server. This means that your data, including usernames and passwords, is only ever visible on the client side. Only the encrypted store is saved to disk on the server side. The AES encryption key is generated from the client password using PBKDF2 key derivation. In addition to the store being encrypted, the client must prove that they know the server password before they can load or commit the store. This means that even if an attacker is ever able to uncover the server password, they still will not be able to read the store without the client password. This security model should guarantee that an attacker can only realistically uncover your passwords if they can guess both the server password and the client password. If an attacker can only guess the server password alone, they could still overwrite the store to delete your passwords. This should restrict most attacks to brute force attacks on the server and client passwords.

### Defense

Once an attacker has the encrypted store, they can perform an offline brute force attack on the client password and there isn't much that can be done. However, passman implements a few measures to slow attackers down when performing brute force attacks on the server password, which is required to obtain the encrypted store. After 5 failed authentication attempts in a row across all clients, all authentication attempts will fail for the next 5 minutes. After a particular client fails to authenticate 25 times in a row, they are banned and any further connection attempts will be refused by the server. The client can view how many failed authentication attempts have been made and the timestamp of the most recent one through the web interface. Each time a client fails to authenticate, the server logs the incident in the `auth.log` file with the timestamp and endpoint of the client. Each time a client is banned, the server logs the incident in the `ban.log` file with the timestamp and endpoint of the client. While the logs persist between server restarts, the count of failed authentications and which endpoints are banned does not persist. You are responsible for noticing that the failed authentication count is increasing and that the timestamp is recent. This indicates that someone unauthorized has been trying to authenticate. You should then shut the server down to prevent any further authentication attempts, then review the log files to see who has been trying to access the server and take appropriate action, for instance strengthening the server device's firewall rules.

### Best Practices

The best way to keep your passwords secure is to pick strong server and client passwords. You should generate a strong password using a password generator, although they may be hard to remember. Additionally, you should check the failed authentication count regularly so you can identify when someone other than you is trying to access your passwords. Choosing a random unreserved port number to run your server on can help keep individuals over the internet from finding your server if you choose to port forward, although note that this does not provide any actual security against someone using a port scanner. I also recommend that you don't use a domain name for your passman server, and instead just memorize your server's IP address to help prevent individuals over the internet from finding your server and to avoid the potential of DNS attacks. Lastly, when signing up for a new site, make sure that you generate a new random password each time rather than reusing the same ones over and over again.

## Certificates

Usually you need to pay a certificate authority to sign a certificate for you so that clients can verify the authenticity of the server they are communicating with, however, since passman is intended for private use, this isn't necessary. passman will generate a self-signed root certificate for you that will expire after 10 years. You may need to delete the old certificate and generate a new one by restarting the server if the old one expires. When you first try to connect to the passman server through your browser, it should warn you that the certificate is invalid. Double check the certificate and verify that you are connecting to the right server. Your browser may let you accept the invalid certificate, but it might become bothersome to have to double check it each time the browser prompts you. Alternatively, you can add the root certificate `certificate.pem` as a root authority to your browser. Note that you should generally be careful about adding root certificates, since adding a malicious one can be extremely dangerous. After doing this, your browser should now verify that the server certificate is valid.
