async function loadStore(serverPassword) {
    const response = await fetch("store", {
        "headers": {
            "Server-Token": serverPassword
        }
    });
    if(!response.ok)
        throw new Error("store not found");
    
    const ciphertext = await response.text();
    if(!ciphertext)
        return [];

    // TODO: ciphertext is actually plaintext for now
    const store = JSON.parse(ciphertext);

    // Validate store
    if(!Array.isArray(store))
            throw new Error("store was invalid");

    for(const entry of store)
        if(typeof entry !== "string")
            throw new Error("entry was invalid in store");

    return store;
}

async function postStore(store, serverPassword) {
    const response = await fetch("store", {
        "method": "POST",
        "headers": {
            "Server-Token": serverPassword
        },
        "body": JSON.stringify(store)
    });
    if(!response.ok)
        throw new Error("Could not post store");
}

async function loadEvent(store) {
    const serverPassword = document.getElementById("server_password");
    if(!serverPassword.value) {
        alert("Invalid server password");
        return;
    }

    try {
        store = await loadStore(serverPassword.value);
        renderStore(store);
    } catch(e) {
        alert("Error occurred while loading store");
    }
}

async function insertEvent(store) {
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

    const entry = textElement.value;
    
    store.push(entry);

    try {
        await postStore(store, serverPassword.value);

        const storeElement = document.getElementById("store");
        storeElement.appendChild(createEntryElement(entry));
    } catch(e) {
        store.pop();
        alert("Error updating store");
    }
}

function createEntryElement(entry) {
    const entryElement = document.createElement("li");
    entryElement.innerText = entry;
    return entryElement;
}

function renderStore(store) {
    const storeElement = document.getElementById("store");
    
    // Clear children
    while(storeElement.firstChild)
        storeElement.removeChild(storeElement.lastChild);

    // Populate children
    for(const entry of store)
        storeElement.appendChild(createEntryElement(entry));
}

async function init() {
    let store = [];

    const loadButtonElement = document.getElementById("load_button");
    loadButtonElement.addEventListener("mousedown",
        (mouseEvent) => loadEvent(store));

    const insertButtonElement = document.getElementById("insert_button");
    insertButtonElement.addEventListener("mousedown",
        (mouseEvent) => insertEvent(store));
}

init();
