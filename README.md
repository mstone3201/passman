# passman

Hello world!

## TODO:

* Prevent client from overwriting store if they are out of date
    * Currently, if one client gets behind another and their store is out of date, when they insert something without fetching the new store, they will overwrite the store
    * Add unique value to POSTs, they should match the number retrieved from a GET
        * Unique value could be a hash of the store, so only a client with a store that agrees with the server can POST
    * If a client makes a POST with the wrong unique value, then they are out of date, should request the new store
    * Could be enforced by the client or the server
* Server password is visible
    * Shouldn't pass the server password as a command line argument, need to obfuscate it
    * Should obfuscate the server password on the website as well
    * Investigate using a KDF to make it harder to guess with brute force attacks
    * Could also just make the password randomly generated and require the client to write it down somewhere secure
* Store should be encrypted
    * Client picks a password and encrypts the store with it
    * Only someone with the client password will be able to view the store, not even the server
    * Also investigate using KDF to make it harder to brute force the password
