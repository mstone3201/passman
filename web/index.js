async function loadStore() {
    const response = await fetch("store");
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

async function postStore(store) {
    const response = await fetch("store", {
        "method": "POST",
        "body": JSON.stringify(store)
    });
    if(!response.ok)
        throw new Error("Could not post store");
}

async function insertEvent(store) {
    const textElement = document.getElementById("insert_text");
    if(!textElement.value)
        alert("Invalid input");
    else {
        const entry = textElement.value;
        
        store.push(entry);

        try {
            await postStore(store);

            const storeElement = document.getElementById("store");
            storeElement.appendChild(createEntryElement(entry));
        } catch(e) {
            alert("Error inserting into store");
        }
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
    try {
        const store = await loadStore();
        renderStore(store);

        const insertButtonElement = document.getElementById("insert_button");
        insertButtonElement.addEventListener("mousedown",
            (mouseEvent) => insertEvent(store));
    } catch(e) {
        console.error(e);
        alert("Error occurred while loading store");
    }
}

init();
