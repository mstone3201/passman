// Class definitions

class Store {
    value = [];
    storeHash;
    serverPassword;

    async load() {
        const response = await fetch("store", {
            "headers": {
                "Server-Token": this.serverPassword
            }
        });
        if(!response.ok)
            throw new Error("Store not found");

        const ciphertext = await response.arrayBuffer();
        if(!ciphertext.byteLength) {
            this.value = [];
            
            const hash = await crypto.subtle.digest("SHA-512",
                new ArrayBuffer());
            this.storeHash = btoa(
                String.fromCodePoint(...new Uint8Array(hash)));
            return;
        }
    
        // TODO: decrypt ciphertext
        const plaintext = ciphertext;

        const store = JSON.parse(new TextDecoder().decode(plaintext));
    
        // Validate store
        if(!Array.isArray(store))
                throw new Error("Store was invalid");
    
        for(const entry of store)
            if(typeof entry !== "string")
                throw new Error("Entry was invalid in store");
    
        this.value = store;

        // Hash the store
        const hash = await crypto.subtle.digest("SHA-512", ciphertext);
        this.storeHash = btoa(String.fromCodePoint(...new Uint8Array(hash)));
    }

    async commit() {
        const plaintext = new TextEncoder().encode(JSON.stringify(this.value));

        // TODO: encrypt plaintext
        const ciphertext = plaintext;

        const response = await fetch("store", {
            "method": "POST",
            "headers": {
                "Server-Token": this.serverPassword,
                "Store-Hash": this.storeHash
            },
            "body": new TextDecoder().decode(ciphertext)
        });
        if(!response.ok)
            throw new Error("Could not commit store");

        const hash = await crypto.subtle.digest("SHA-512", ciphertext);
        this.storeHash = btoa(String.fromCodePoint(...new Uint8Array(hash)));
    }
}

// Global variables

const store = new Store();

// Free functions

async function loadEvent() {
    const serverPassword = document.getElementById("server_password");
    if(!serverPassword.value) {
        alert("Invalid server password");
        return;
    }

    store.serverPassword = serverPassword.value;

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

    const textElement = document.getElementById("insert_text");
    if(!textElement.value) {
        alert("Invalid input");
        return;
    }

    store.serverPassword = serverPassword.value;

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
