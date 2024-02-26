// Class definitions

class Store {
    value = [];
    serverPassword;

    async load() {
        const response = await fetch("store", {
            "headers": {
                "Server-Token": this.serverPassword
            }
        });
        if(!response.ok)
            throw new Error("Store not found");
        
        const ciphertext = await response.text();
        if(!ciphertext) {
            this.value = [];
            return;
        }
    
        // TODO: ciphertext is actually plaintext for now
        const store = JSON.parse(ciphertext);
    
        // Validate store
        if(!Array.isArray(store))
                throw new Error("Store was invalid");
    
        for(const entry of store)
            if(typeof entry !== "string")
                throw new Error("Entry was invalid in store");
    
        this.value = store;
    }

    async commit() {
        const response = await fetch("store", {
            "method": "POST",
            "headers": {
                "Server-Token": this.serverPassword
            },
            "body": JSON.stringify(this.value)
        });
        if(!response.ok)
            throw new Error("Could not commit store");
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
