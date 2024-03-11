# passman

Hello world!

## TODO:

* Improve Security of passwords
    * Shouldn't pass server password as a command line argument
    * Should obfuscate passwords everywhere we need to enter them
    * Maybe block a client for a while if they fail to authenticate a certain number of times to make it harder to brute force
* Implement password management features
    * Obsucate password, make it so you have to click to reveal it
    * Should be able to insert new entries
        * When creating an entry previously used tags and names should be suggested
        * Should have an option to manually type in a password or automatically generate one
            * Might want to add options for desired or undesired characters to accomodate for sites with strict password policies
            * Maybe include an indicator for how strong or weak the password is
    * Should remember the server password so that everything is loaded automatically when connecting
    * Similarly, should remember the client password
    * Should be able to search for an entry by name or tag
        * Entry can have multiple tags, multiple entries might want to share tags
        * For instance, you could have an email tag, and see all your accounts for different email services
