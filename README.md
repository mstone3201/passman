# passman

Hello world!

## TODO:

* Store should be encrypted
    * Client picks a password and encrypts the store with it
    * Only someone with the client password will be able to view the store, not even the server
* Improve Security of passwords
    * Shouldn't pass server password as a command line argument
    * Should obfuscate passwords everywhere we need to enter them
    * Investigate using a KDF to make it harder to guess with brute force attacks
    * Investigate other methods to make it harder to brute force
        * Maybe block a client for a while if they fail to authenticate a certain number of times
* Implement password management features on the site
    * Table to display data
    * Should have a name column, tags column, username column, password column
    * Obsucate password, make it so you have to click to reveal it
    * Should be able to insert new entries
        * When creating an entry previously used tags and names should be suggested
        * username should be unique for each name to prevent user mistakes
        * Should have an option to manually type in a password or automatically generate one
            * Might want to add options for desired or undesired characters to accomodate for sites with strict password policies
            * Maybe include an indicator for how strong or weak the password is
    * Should be able to edit existing entries
    * Should be able to delete existing entries
    * Should remember the server password so that everything is loaded automatically when connecting
    * Similarly, should remember the client password
    * Should be able to search for an entry by name or tag
        * Entry can have multiple tags, multiple entries might want to share tags
        * For instance, you could have an email tag, and see all your accounts for different email services
