# passman

Hello world!

## TODO:

* Have server save the store to disk
    * After a POST start a 5 minute timer, then save the file
    * POSTs within the timer are included, but don't extend it
    * A POST after the timer expires and the file is written starts a new timer
* Prevent client from overwriting store if they are out of date
    * Currently, if one client gets behind another and their store is out of date, when they insert something without fetching the new store, they will overwrite the store
    * Add unique value to POSTs, they should match the number retrieved from a GET
        * Unique value could be a hash of the store, so only a client with a store that agrees with the server can POST
    * If a client makes a POST with the wrong unique value, then they are out of date, should request the new store
    * Could be enforced by the client or the server
* Only privileged clients should be able to GET or POST the store
    * Client should be required to prove that it knows the server password
    * Maybe use the Authorization HTTP headers for this
    * Since we are using HTTPS one possibiltiy is to just send the server password as plaintext
        * Might be better to send a hash of the password
    * Even though we are using HTTPS, our certificates are self-signed, so a client might accidentally accept a certificate from a MITM
        * If the store is client only encrypted, we don't really need to worry about them stealing the data, but they could do something destructive like overwriting the store
        * Could have the client sign the store with the server password before POSTing, then the server can verify that the signature is correct
            * Want to do this when the client GETs the store as well, so the MITM doesn't send them an old/invalid store and cause the client to accidentally write back a store which is wrong
            * This should also address the problem of client writing an old store even if there is no MITM
                * Rather than sending the unique value, we send the signature
                * When the client GETs it receives a signature for the store it retrieves
                * When the client POSTs it sends the old signature along with the new signature and store
                * The server verifies that the old signature matches the signature of the store it has
                    * If the store is outdated, then the signature won't match, so the MITM can't mess things up by replaying an old store
                    * If a client has an outdated store, similarly the signature won't match so the server rejects the POST
                * The server verifies that the new signature is a valid signature of the new store, so it knows a privileged client sent it
* Server password is visible in the command line
    * Should keep the password as hidden as possible on the server side
    * Investigate using a KDF to make it harder to guess with brute force attacks
    * Could also just make the password randomly generated and require the client to write it down somewhere secure
* Store should be encrypted
    * Client picks a password and encrypts the store with it
    * Only someone with the client password will be able to view the store, not even the server
    * Also investigate using KDF to make it harder to brute force this password
