// Constants

const SALT_SIZE = 32;
const KEY_SIZE = 256;
const IV_SIZE = 32;
const TAG_SIZE = 128;
const KDF_ITERATIONS = 1000000;

// Class definitions

class Store {
    value = [];
    storeHash;
    serverPassword;
    clientPassword;

    async load() {
        const response = await fetch("store", {
            "headers": {
                "Server-Token": this.serverPassword
            }
        });
        if(!response.ok)
            throw new Error("Store not found");

        const data = new Uint8Array(await response.arrayBuffer());
        if(!data.byteLength) {
            this.value = [];
            
            const hash = new Uint8Array(await crypto.subtle.digest("SHA-512",
                new Uint8Array()));
            this.storeHash = btoa(String.fromCodePoint(...hash));
            return;
        }
    
        // Decrypt ciphertext
        const salt = data.subarray(0, SALT_SIZE);
        const iv = data.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
        const ciphertext = data.subarray(SALT_SIZE + IV_SIZE);

        const [, key] = await deriveKey(this.clientPassword, salt);

        const plaintext = await decrypt(iv, ciphertext, key);

        const store = JSON.parse(new TextDecoder().decode(plaintext));

        // Validate store
        if(!Array.isArray(store))
            throw new Error("Store was invalid");

        for(const entry of store)
            if(typeof entry !== "string")
                throw new Error("Entry was invalid in store");

        this.value = store;

        // Hash the store
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-512",
            data));
        this.storeHash = btoa(String.fromCodePoint(...hash));
    }

    async commit() {
        const plaintext = new TextEncoder().encode(JSON.stringify(this.value));

        // Encrypt plaintext
        const [salt, key] = await deriveKey(this.clientPassword);

        const [iv, ciphertext] = await encrypt(plaintext, key);

        const data = new Uint8Array(salt.byteLength + iv.byteLength
                + ciphertext.byteLength);
        data.set(salt);
        data.set(iv, salt.byteLength);
        data.set(ciphertext, salt.byteLength + iv.byteLength);

        const response = await fetch("store", {
            "method": "POST",
            "headers": {
                "Server-Token": this.serverPassword,
                "Store-Hash": this.storeHash
            },
            "body": data
        });
        if(!response.ok)
            throw new Error("Could not commit store");

        const hash = new Uint8Array(await crypto.subtle.digest("SHA-512",
            data));
        this.storeHash = btoa(String.fromCodePoint(...hash));
    }
}

// Global variables

const store = new Store();

// Free functions

async function deriveKey(password, salt = undefined) {
    const rawKey = await crypto.subtle.importKey("raw",
        new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);

    if(!salt)
        salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    
    return [salt, await crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            "hash": "SHA-512",
            "salt": salt,
            "iterations": KDF_ITERATIONS
        },
        rawKey, { "name": "AES-GCM", "length": KEY_SIZE }, false,
        ["encrypt", "decrypt"])];
}

async function encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(32));
    return [iv, new Uint8Array(await crypto.subtle.encrypt({
            "name": "AES-GCM",
            "iv": iv,
            "tagLength": TAG_SIZE
        }, key, plaintext))];
}

async function decrypt(iv, ciphertext, key) {
    return new Uint8Array(await crypto.subtle.decrypt({
            "name": "AES-GCM",
            "iv": iv,
            "tagLength": TAG_SIZE
        }, key, ciphertext));
}

async function loadEvent() {
    const serverPassword = document.getElementById("server_password");
    if(!serverPassword.value) {
        alert("Invalid server password");
        return;
    }

    store.serverPassword = serverPassword.value;

    const clientPassword = document.getElementById("client_password");
    if(!clientPassword.value) {
        alert("Invalid client password");
        return;
    }

    store.clientPassword = clientPassword.value;

    try {
        await store.load();
    } catch(e) {
        alert("Error occurred while loading store");
        return;
    }

    const storeElement = document.getElementById("store");
        
    // Clear children
    while(storeElement.firstChild)
        storeElement.removeChild(storeElement.lastChild);

    // Populate children
    for(const entry of store.value) {
        const entryElement = document.createElement("li");
        entryElement.innerText = entry;
        storeElement.appendChild(entryElement);
    }
}

async function insertEvent() {
    const serverPassword = document.getElementById("server_password");
    if(!serverPassword.value) {
        alert("Invalid server password");
        return;
    }

    store.serverPassword = serverPassword.value;

    const clientPassword = document.getElementById("client_password");
    if(!clientPassword.value) {
        alert("Invalid client password");
        return;
    }

    store.clientPassword = clientPassword.value;

    const textElement = document.getElementById("insert_text");
    if(!textElement.value) {
        alert("Invalid input");
        return;
    }

    const entry = textElement.value;
    
    store.value.push(entry);

    try {
        await store.commit();
    } catch(e) {
        store.value.pop();
        alert("Error updating store");
        return;
    }

    const entryElement = document.createElement("li");
    entryElement.innerText = entry;
    document.getElementById("store").appendChild(entryElement);
}

async function init() {
    const loadButtonElement = document.getElementById("load_button");
    loadButtonElement.addEventListener("mousedown", loadEvent);

    const insertButtonElement = document.getElementById("insert_button");
    insertButtonElement.addEventListener("mousedown", insertEvent);
}

init();
