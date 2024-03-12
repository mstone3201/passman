// Constants

const SALT_SIZE = 32;
const KEY_SIZE = 256;
const IV_SIZE = 32;
const TAG_SIZE = 128;
const KDF_ITERATIONS = 1000000;

// Document constants

const GENERATE_TEXT_ELEMENT = document.getElementById("generate_text");
const GENERATE_BUTTON_ELEMENT = document.getElementById("generate_button");
const PASSWORD_STRENGTH_ELEMENT = document.getElementById("password_strength");
const GROUPS_ELEMENT = document.getElementById("groups");
const ADD_GROUP_BUTTON_ELEMENT = document.getElementById("add_group_button");

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
            this.name = nameTextElement.value.trim();
        });
        nameElement.appendChild(nameTextElement);

        const tagsElement = document.createElement("td");
        rowElement.appendChild(tagsElement);

        const tagsTextElement = document.createElement("input");
        tagsTextElement.type = "text";
        tagsTextElement.value = this.tags.join(", ");
        tagsTextElement.addEventListener("input", () => {
            this.tags = [];

            for(const tag of tagsTextElement.value.split(",")) {
                const trimmed = tag.trim();

                if(trimmed)
                    this.tags.push(trimmed);
            }
        });
        tagsElement.appendChild(tagsTextElement);

        const usernameElement = document.createElement("td");
        rowElement.appendChild(usernameElement);

        const usernameTextElement = document.createElement("input");
        usernameTextElement.type = "text";
        usernameTextElement.value = this.username;
        usernameTextElement.addEventListener("input", () => {
            this.username = usernameTextElement.value.trim();
        });
        usernameElement.appendChild(usernameTextElement);

        const passwordElement = document.createElement("td");
        rowElement.appendChild(passwordElement);

        const passwordTextElement = document.createElement("input");
        passwordTextElement.type = "text";
        passwordTextElement.value = this.password;
        passwordTextElement.addEventListener("input", () => {
            this.password = passwordTextElement.value.trim();
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

class Group {
    options;
    count;

    constructor(options, count) {
        this.options = options;
        this.count = count;
    }

    createElement() {
        const divElement = document.createElement("div");
        divElement.classList.add("group");

        const optionsElement = document.createElement("textarea");
        optionsElement.cols = 32;
        optionsElement.rows = 4;
        optionsElement.placeholder = "Enter characters";
        optionsElement.value = this.options;
        optionsElement.addEventListener("input", () => {
            this.options = optionsElement.value.replaceAll(/\s/g, "");
        });
        divElement.appendChild(optionsElement);

        const labelElement = document.createElement("label");
        labelElement.innerText = "Count:";
        divElement.appendChild(labelElement);

        const countElement = document.createElement("input");
        countElement.type = "text";
        countElement.value = this.count;
        countElement.addEventListener("input", () => {
            const val = Number(countElement.value);

            if(!isNaN(val) && val >= 0)
                this.count = val;
        });
        divElement.appendChild(countElement);

        const deleteElement = document.createElement("button");
        deleteElement.innerText = "X";
        deleteElement.addEventListener("mousedown", () => {
            generator.erase(this);
            generator.draw();
        });
        divElement.appendChild(deleteElement);

        return divElement;
    }
}

class Generator {
    groups = new Set([new Group("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST\
UVWXYZ1234567890-=!@#$%^&*()_+[]|{};:,./<>?", 32)]);

    insert(group) {
        this.groups.add(group);
    }

    erase(group) {
        this.groups.delete(group);
    }

    draw() {
        // Clear groups
        for(const groupElement of GROUPS_ELEMENT.querySelectorAll("div.group"))
            groupElement.remove();

        // Add groups
        for(const group of this.groups)
            GROUPS_ELEMENT.appendChild(group.createElement());
    }
}

// Global variables

const store = new Store();
const generator = new Generator();

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

// Uniform random value in the range [0, upperBound)
function randomValue(upperBound) {
    if(upperBound > 2 ** 16)
        throw new Error("Upper bound exceeded 65536");

    // Get unbiased random number
    const max = 2n ** 64n;
    const mod = BigInt(upperBound);
    const limit = max - max % mod;

    const index = new BigUint64Array(1);

    // The probability of looping again is at most 2^16 / 2^64 = 2^-48
    // On my machine, 1 million iterations takes under .2 second
    // The probability of looping 1 million times is 2^-48000000
    // Realistically the user will never wait for very long
    do {
        crypto.getRandomValues(index);
    } while(index[0] >= limit);

    return Number(index[0] % mod);
}

function choice(options) {
    return options[randomValue(options.length)];
}

function shuffle(values) {
    for(let i = values.length - 1; i > 0; --i) {
        const j = randomValue(i + 1);
        
        // Swap
        const tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
    }

    return values;
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

function addGroupEvent() {
    generator.insert(new Group("", 1));

    generator.draw();
}

function generateEvent() {
    let password = "";
    let length = 0;
    let combinations = BigInt(1);

    // Generate password
    for(const group of generator.groups) {
        if(group.options.length) {
            for(let i = 0; i < group.count; ++i)
                password += choice(group.options);

            length += group.count;
            combinations *= BigInt(group.options.length) ** BigInt(group.count);
        }
    }

    password = shuffle(Array.from(password)).join("");

    GENERATE_TEXT_ELEMENT.value = password;
    PASSWORD_STRENGTH_ELEMENT.innerText = "Length: " + length +
        ", Combinations: " + combinations;
}

// Initialization

GENERATE_BUTTON_ELEMENT.addEventListener("mousedown", generateEvent)
ADD_GROUP_BUTTON_ELEMENT.addEventListener("mousedown", addGroupEvent);
LOAD_BUTTON_ELEMENT.addEventListener("mousedown", loadEvent);
INSERT_BUTTON_ELEMENT.addEventListener("mousedown", insertEvent);
COMMIT_BUTTON_ELEMENT.addEventListener("mousedown", commitEvent);

generator.draw();
store.draw();

generateEvent();
