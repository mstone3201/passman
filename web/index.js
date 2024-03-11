// Constants

const SALT_SIZE = 32;
const KEY_SIZE = 256;
const IV_SIZE = 32;
const TAG_SIZE = 128;
const KDF_ITERATIONS = 1000000;

// Document constants

const SERVER_PASSWORD_ELEMENT = document.getElementById("server_password");
const CLIENT_PASSWORD_ELEMENT = document.getElementById("client_password");
const LOAD_BUTTON_ELEMENT = document.getElementById("load_button");

const INSERT_NAME_ELEMENT = document.getElementById("insert_name");
const INSERT_TAGS_ELEMENT = document.getElementById("insert_tags");
const INSERT_USERNAME_ELEMENT = document.getElementById("insert_username");
const INSERT_PASSWORD_ELEMENT = document.getElementById("insert_password");
const INSERT_BUTTON_ELEMENT = document.getElementById("insert_button");

const COMMIT_BUTTON_ELEMENT = document.getElementById("commit_button");
const STORE_ELEMENT = document.getElementById("store");

// Class definitions

class Entry {
    name;
    tags = [];
    username;
    password;

    constructor(name, tags, username, password) {
        this.name = name;
        this.tags = tags;
        this.username = username;
        this.password = password;
    }

    createElement() {
        const rowElement = document.createElement("tr");

        const nameElement = document.createElement("th");
        rowElement.appendChild(nameElement);

        const nameTextElement = document.createElement("input");
        nameTextElement.type = "text";
        nameTextElement.value = this.name;
        nameTextElement.addEventListener("input", () => {
            this.name = nameTextElement.value;
        });
        nameElement.appendChild(nameTextElement);

        const tagsElement = document.createElement("td");
        rowElement.appendChild(tagsElement);

        const tagsTextElement = document.createElement("input");
        tagsTextElement.type = "text";
        tagsTextElement.value = this.tags.toString();
        tagsTextElement.addEventListener("input", () => {
            this.tags = tagsTextElement.value.split(",");
        });
        tagsElement.appendChild(tagsTextElement);

        const usernameElement = document.createElement("td");
        rowElement.appendChild(usernameElement);

        const usernameTextElement = document.createElement("input");
        usernameTextElement.type = "text";
        usernameTextElement.value = this.username;
        usernameTextElement.addEventListener("input", () => {
            this.username = usernameTextElement.value;
        });
        usernameElement.appendChild(usernameTextElement);

        const passwordElement = document.createElement("td");
        rowElement.appendChild(passwordElement);

        const passwordTextElement = document.createElement("input");
        passwordTextElement.type = "text";
        passwordTextElement.value = this.password;
        passwordTextElement.addEventListener("input", () => {
            this.password = passwordTextElement.value;
        });
        passwordElement.appendChild(passwordTextElement);

        const deleteElement = document.createElement("td");
        rowElement.appendChild(deleteElement);

        const buttonElement = document.createElement("button");
        buttonElement.innerText = "X";
        buttonElement.addEventListener("mousedown", () => {
            store.erase(this);
            store.draw();
        });
        deleteElement.appendChild(buttonElement);

        return rowElement;
    }
}

class Store {
    entries = new Set();
    storeHash;

    async load(serverPassword, clientPassword) {
        const response = await fetch("store", {
            "headers": {
                "Server-Token": serverPassword
            }
        });
        if(!response.ok)
            throw new Error("Store not found");

        const data = new Uint8Array(await response.arrayBuffer());
        if(!data.byteLength) {
            this.entries.clear();
            
            const hash = new Uint8Array(await crypto.subtle.digest("SHA-512",
                new Uint8Array()));
            this.storeHash = btoa(String.fromCodePoint(...hash));
            return;
        }
    
        // Decrypt ciphertext
        const salt = data.subarray(0, SALT_SIZE);
        const iv = data.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
        const ciphertext = data.subarray(SALT_SIZE + IV_SIZE);

        const [, key] = await deriveKey(clientPassword, salt);
        const plaintext = await decrypt(iv, ciphertext, key);
        const store = JSON.parse(new TextDecoder().decode(plaintext));

        this.entries.clear();
        for(const entry of store)
            this.entries.add(new Entry(entry.name, entry.tags, entry.username,
                entry.password));

        // Hash the store
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-512",
            data));
        this.storeHash = btoa(String.fromCodePoint(...hash));
    }

    async commit(serverPassword, clientPassword) {
        const plaintext = new TextEncoder().encode(
            JSON.stringify(Array.from(this.entries)));

        // Encrypt plaintext
        const [salt, key] = await deriveKey(clientPassword);

        const [iv, ciphertext] = await encrypt(plaintext, key);

        const data = new Uint8Array(salt.byteLength + iv.byteLength
                + ciphertext.byteLength);
        data.set(salt);
        data.set(iv, salt.byteLength);
        data.set(ciphertext, salt.byteLength + iv.byteLength);

        const response = await fetch("store", {
            "method": "POST",
            "headers": {
                "Server-Token": serverPassword,
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

    insert(entry) {
        this.entries.add(entry);
    }

    erase(entry) {
        this.entries.delete(entry);
    }

    draw() {
        // Clear store
        const oldBodyElement = STORE_ELEMENT.querySelector("tbody");
        if(oldBodyElement)
            oldBodyElement.remove();

        const oldFootElement = STORE_ELEMENT.querySelector("tfoot");
        if(oldFootElement)
            oldFootElement.remove();

        // Add entries
        const bodyElement = document.createElement("tbody");
        STORE_ELEMENT.appendChild(bodyElement);

        for(const entry of this.entries)
            bodyElement.appendChild(entry.createElement());

        // Add footer
        const footElement = document.createElement("tfoot");
        STORE_ELEMENT.appendChild(footElement);

        const rowElement = document.createElement("tr");
        footElement.appendChild(rowElement);

        const dataElement = document.createElement("td");
        dataElement.colSpan = 4;
        dataElement.innerText = "Total: " + this.entries.size;
        rowElement.appendChild(dataElement);
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
    try {
        await store.load(SERVER_PASSWORD_ELEMENT.value,
            CLIENT_PASSWORD_ELEMENT.value);

        store.draw();
    } catch(e) {
        alert("Error occurred while loading store");
        return;
    }
}

function insertEvent() {
    store.insert(new Entry(INSERT_NAME_ELEMENT.value,
        INSERT_TAGS_ELEMENT.value.split(","), INSERT_USERNAME_ELEMENT.value,
        INSERT_PASSWORD_ELEMENT.value));
        
    store.draw();
}

async function commitEvent() {
    try {
        await store.commit(SERVER_PASSWORD_ELEMENT.value,
            CLIENT_PASSWORD_ELEMENT.value);
    } catch(e) {
        alert("Error committing store");
        return;
    }
}

// Initialization

LOAD_BUTTON_ELEMENT.addEventListener("mousedown", loadEvent);
INSERT_BUTTON_ELEMENT.addEventListener("mousedown", insertEvent);
COMMIT_BUTTON_ELEMENT.addEventListener("mousedown", commitEvent);

store.draw();
