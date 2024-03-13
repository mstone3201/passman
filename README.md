# passman

Hello world!

## TODO:

* Improve Security of passwords
    * Shouldn't pass server password as a command line argument
    * Should obfuscate passwords everywhere we need to enter them
    * Maybe block a client for a while if they fail to authenticate a certain number of times to make it harder to brute force
* Implement password management features
    * Obfuscate password, make it so you have to click to reveal it
    * When creating an entry, previously used tags and names should be suggested
    * Maybe include an indicator for how strong or weak the generated password is
    * Should remember the server password so that everything is loaded automatically when connecting
    * Similarly, should remember the client password
