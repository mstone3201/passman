// Constants

const SALT_SIZE = 32;
const KEY_SIZE = 256;
const IV_SIZE = 32;
const TAG_SIZE = 128;
const KDF_ITERATIONS = 1000000;

const DELETE_SYMBOL = "X";
const UP_ARROW_SYMBOL = "⮝";
const DOWN_ARROW_SYMBOL = "⮟";

// Document constants

const AUTH_INFO_FAILS_ELEMENT = document.getElementById("auth_info_fails");
const AUTH_INFO_LOCK_ELEMENT = document.getElementById("auth_info_lock");

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
const SEARCH_QUERY_ELEMENT = document.getElementById("search_query");
const STORE_ELEMENT = document.getElementById("store");
const STORE_TOTAL_ELEMENT = document.getElementById("store_total");

// Class definitions

class Entry {
    name;
    tags = [];
    date;
    username;
    password;

    constructor(name, tags, date, username, password) {
        this.name = name;
        this.tags = tags;
        this.date = date;
        this.username = username;
        this.password = password;
    }

    createElement() {
        const rowElement = document.createElement("tr");
        rowElement.entry = this;
        rowElement.classList.add("show");

        const dateTextElement = document.createElement("input");
        dateTextElement.type = "text";
        dateTextElement.name = "date";
        dateTextElement.classList.add("date");
        dateTextElement.readOnly = true;
        dateTextElement.value = getDateString(this.date);

        const nameElement = document.createElement("th");
        rowElement.appendChild(nameElement);

        const nameTextElement = document.createElement("input");
        nameTextElement.type = "text";
        nameTextElement.name = "name";
        nameTextElement.autocomplete = "off";
        nameTextElement.value = this.name;
        nameTextElement.addEventListener("input", () => {
            this.name = nameTextElement.value.trim();

            this.date = Date.now();
            dateTextElement.value = getDateString(this.date); 
        });
        nameTextElement.addEventListener("focusout", () => {
            nameTextElement.value = this.name;
        });
        nameElement.appendChild(nameTextElement);

        const tagsElement = document.createElement("td");
        rowElement.appendChild(tagsElement);

        const tagsTextElement = document.createElement("input");
        tagsTextElement.type = "text";
        tagsTextElement.name = "tags";
        tagsTextElement.autocomplete = "off";
        tagsTextElement.value = this.tags.join(", ");
        tagsTextElement.addEventListener("input", () => {
            this.tags = [];

            for(const tag of tagsTextElement.value.split(",")) {
                const trimmed = tag.trim();

                if(trimmed)
                    this.tags.push(trimmed);
            }

            this.date = Date.now();
            dateTextElement.value = getDateString(this.date);
        });
        tagsTextElement.addEventListener("focusout", () => {
            tagsTextElement.value = this.tags.join(", ");
        });
        tagsElement.appendChild(tagsTextElement);

        const dateElement = document.createElement("td");
        rowElement.appendChild(dateElement);

        dateElement.appendChild(dateTextElement);

        const usernameElement = document.createElement("td");
        rowElement.appendChild(usernameElement);

        const usernameTextElement = document.createElement("input");
        usernameTextElement.type = "text";
        usernameTextElement.name = "username";
        usernameTextElement.autocomplete = "off";
        usernameTextElement.value = this.username;
        usernameTextElement.addEventListener("input", () => {
            this.username = usernameTextElement.value.trim();

            this.date = Date.now();
            dateTextElement.value = getDateString(this.date);
        });
        usernameTextElement.addEventListener("focusout", () => {
            usernameTextElement.value = this.username;
        });
        usernameElement.appendChild(usernameTextElement);

        const passwordElement = document.createElement("td");
        rowElement.appendChild(passwordElement);

        const passwordTextElement = document.createElement("input");
        passwordTextElement.type = "password";
        passwordTextElement.name = "password";
        passwordTextElement.autocomplete = "off";
        passwordTextElement.value = this.password;
        passwordTextElement.addEventListener("input", () => {
            passwordTextElement.type = "password";

            this.password = passwordTextElement.value.trim();

            this.date = Date.now();
            dateTextElement.value = getDateString(this.date);
        });
        passwordTextElement.addEventListener("focusin", () => {
            passwordTextElement.type = "text";
            passwordTextElement.select();
        });
        passwordTextElement.addEventListener("focusout", () => {
            passwordTextElement.type = "password";
            passwordTextElement.value = this.password;
        });
        passwordElement.appendChild(passwordTextElement);

        const deleteElement = document.createElement("td");
        rowElement.appendChild(deleteElement);

        const buttonElement = document.createElement("button");
        buttonElement.innerText = DELETE_SYMBOL;
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
        serverPassword = serverPassword.trim();
        clientPassword = clientPassword.trim();

        if(!serverPassword)
            serverPassword = "none";
        if(!clientPassword)
            clientPassword = "none";

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

        // Decompress
        const decompressed = await decompress(plaintext);

        // Parse store
        const store = JSON.parse(new TextDecoder().decode(decompressed));

        this.entries.clear();
        for(const entry of store)
            this.entries.add(new Entry(entry.name, entry.tags, entry.date,
                entry.username, entry.password));

        // Hash the store
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-512",
            data));
        this.storeHash = btoa(String.fromCodePoint(...hash));
    }

    async commit(serverPassword, clientPassword) {
        serverPassword = serverPassword.trim();
        clientPassword = clientPassword.trim();

        if(!serverPassword)
            serverPassword = "none";
        if(!clientPassword)
            clientPassword = "none";

        const decompressed = new TextEncoder().encode(
            JSON.stringify(Array.from(this.entries)));

        // Compress
        const plaintext = await compress(decompressed);

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
        const bodyElement = STORE_ELEMENT.querySelector("tbody");
        // Clear store
        for(const entry of bodyElement.querySelectorAll("tr"))
            entry.remove();

        // Add entries
        for(const entry of this.entries)
            bodyElement.appendChild(entry.createElement());

        // Update total
        STORE_TOTAL_ELEMENT.innerText = "Total: " + this.entries.size;
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
        optionsElement.name = "options";
        optionsElement.cols = 32;
        optionsElement.rows = 4;
        optionsElement.placeholder = "Enter characters";
        optionsElement.value = this.options;
        optionsElement.addEventListener("input", () => {
            this.options = optionsElement.value.replaceAll(/\s/g, "");
        });
        optionsElement.addEventListener("focusout", () => {
            optionsElement.value = this.options;
        });
        divElement.appendChild(optionsElement);

        const labelElement = document.createElement("span");
        labelElement.innerText = "Count:";
        divElement.appendChild(labelElement);

        const countElement = document.createElement("input");
        countElement.type = "text";
        countElement.name = "count";
        countElement.value = this.count;
        countElement.addEventListener("input", () => {
            const val = Number(countElement.value);

            if(!isNaN(val) && val >= 0)
                this.count = val;
        });
        countElement.addEventListener("focusout", () => {
            countElement.value = this.count;
        });
        divElement.appendChild(countElement);

        const deleteElement = document.createElement("button");
        deleteElement.innerText = DELETE_SYMBOL;
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
const sortOrder = {
    category: "name",
    name: false,
    date: false,
    username: false
};

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

async function compress(decompressed) {
    const gzip = new CompressionStream("gzip");
        
    const gzipWriter = gzip.writable.getWriter();
    gzipWriter.write(decompressed);
    gzipWriter.close();

    const chunks = [];
    const gzipReader = gzip.readable.getReader();
    while(true) {
        const {value, done} = await gzipReader.read();
        if(done) break;

        chunks.push(value);
    }

    const compressed = new Uint8Array(chunks.reduce(
        (acc, val) => acc + val.byteLength, 0
    ));
    let offset = 0;
    for(const chunk of chunks) {
        compressed.set(chunk, offset);

        offset += chunk.byteLength;
    }

    return compressed;
}

async function decompress(compressed) {
    const gzip = new DecompressionStream("gzip");
        
    const gzipWriter = gzip.writable.getWriter();
    gzipWriter.write(compressed);
    gzipWriter.close();

    const chunks = [];
    const gzipReader = gzip.readable.getReader();
    while(true) {
        const {value, done} = await gzipReader.read();
        if(done) break;

        chunks.push(value);
    }

    const decompressed = new Uint8Array(chunks.reduce(
        (acc, val) => acc + val.byteLength, 0
    ));
    let offset = 0;
    for(const chunk of chunks) {
        decompressed.set(chunk, offset);

        offset += chunk.byteLength;
    }

    return decompressed;
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

function getDateString(date) {
    return new Date(date).toLocaleDateString("en-US");
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

    // Sort store
    sortOrder.category = "name";
    sortOrder.name = false;
    sortStoreEvent();

    // Reset search query
    SEARCH_QUERY_ELEMENT.value = "";
}

function insertEvent() {
    tags = [];

    for(const tag of INSERT_TAGS_ELEMENT.value.split(",")) {
        const trimmed = tag.trim();

        if(trimmed)
            tags.push(trimmed);
    }

    store.insert(new Entry(INSERT_NAME_ELEMENT.value.trim(), tags, Date.now(),
        INSERT_USERNAME_ELEMENT.value.trim(),
        INSERT_PASSWORD_ELEMENT.value.trim()));
        
    store.draw();

    sortStoreEvent();

    SEARCH_QUERY_ELEMENT.value = "";
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
    let combinations = BigInt(1);

    // Generate password
    for(const group of generator.groups) {
        if(group.options.length) {
            for(let i = 0; i < group.count; ++i)
                password += choice(group.options);

            combinations *= BigInt(group.options.length) ** BigInt(group.count);
        }
    }

    password = shuffle(Array.from(password)).join("");

    GENERATE_TEXT_ELEMENT.value = password;
    PASSWORD_STRENGTH_ELEMENT.innerText = "Length: " + password.length +
        ", Combinations: " + combinations.toLocaleString("en-US",
            combinations >= 1e9 ? {
                notation: "scientific",
                maximumFractionDigits: 1
            } : {}).toLowerCase();
}

function searchEvent(regex) {
    if(!regex) {
        for(const entry of STORE_ELEMENT.querySelectorAll("tbody tr"))
            entry.classList.add("show");

        STORE_TOTAL_ELEMENT.innerText = "Total: " + store.entries.size;

        return;
    }

    try {
        const regexp = new RegExp(regex);

        let count = 0;
        for(const entry of STORE_ELEMENT.querySelectorAll("tbody tr")) {
            if(entry.entry.name.match(regexp) ||
                entry.entry.tags.some((tag) => tag.match(regexp)) ||
                getDateString(entry.entry.date).match(regexp) ||
                entry.entry.username.match(regexp))
            {
                entry.classList.add("show");

                ++count;
            } else
                entry.classList.remove("show");
        }

        STORE_TOTAL_ELEMENT.innerText = "Total: " + count;
    } catch(e) {
        return;
    }
}

function sortStoreEvent() {
    const bodyElement = STORE_ELEMENT.querySelector("tbody");

    const entries = Array.from(bodyElement.querySelectorAll("tr"));
    entries.sort((a, b) => {
        const left = a.entry[sortOrder.category];
        const right = b.entry[sortOrder.category];

        if(left < right)
            return sortOrder[sortOrder.category] ? 1 : -1;
        if(left > right)
            return sortOrder[sortOrder.category] ? -1 : 1;
        
        return 0;
    });

    for(const entry of entries)
        bodyElement.appendChild(entry);

    // Remove previous category sort class
    STORE_ELEMENT.querySelector("thead th.sort").classList.remove("sort");

    // Set this category to be sorted
    const headElemement = STORE_ELEMENT.querySelector("thead th#"
        + sortOrder.category);
    headElemement.classList.add("sort");
    headElemement.querySelector("#arrow").innerText =
        sortOrder[sortOrder.category] ? UP_ARROW_SYMBOL : DOWN_ARROW_SYMBOL;
}

async function getAuthInfoEvent() {
    try {
        const response = await fetch("auth_info");
        if(!response.ok)
            throw new Error("Authentication info not found");

        const data = new BigUint64Array(await response.arrayBuffer());
        
        AUTH_INFO_FAILS_ELEMENT.innerText = "Failed Authentication Count: "
            + data[0];
        if(data[1])
            AUTH_INFO_FAILS_ELEMENT.innerText += ", Last Fail Time: "
                + new Date(Number(data[1])).toLocaleString("en-US");

        if(data[2] > Date.now()) {
            function countdown() {
                const seconds = Math.floor((Number(data[2]) - Date.now())
                    / 1000);
                if(seconds >= 0) {
                    const minutes = Math.floor(seconds / 60);
                    const remainingSeconds = seconds - minutes * 60;

                    const leadingZero = remainingSeconds < 10 ? "0" : "";

                    AUTH_INFO_LOCK_ELEMENT.innerText = ", Lock Duration: "
                        + minutes + ":" + leadingZero + remainingSeconds;

                    setTimeout(countdown, 1000);
                } else
                    AUTH_INFO_LOCK_ELEMENT.innerText = "";
            };
            countdown();
        }
    } catch(e) {
        alert("Error occurred while getting authentication info");
        return;
    }
}

// Initialization

GENERATE_TEXT_ELEMENT.addEventListener("focusin", () => {
    GENERATE_TEXT_ELEMENT.select();
});
GENERATE_BUTTON_ELEMENT.addEventListener("mousedown", generateEvent);
ADD_GROUP_BUTTON_ELEMENT.addEventListener("mousedown", addGroupEvent);
SERVER_PASSWORD_ELEMENT.addEventListener("focusout", () => {
    SERVER_PASSWORD_ELEMENT.value = SERVER_PASSWORD_ELEMENT.value.trim();
});
CLIENT_PASSWORD_ELEMENT.addEventListener("focusout", () => {
    CLIENT_PASSWORD_ELEMENT.value = CLIENT_PASSWORD_ELEMENT.value.trim();
});
LOAD_BUTTON_ELEMENT.addEventListener("mousedown", async () => {
    await loadEvent();
    getAuthInfoEvent();
});
INSERT_NAME_ELEMENT.addEventListener("focusout", () => {
    INSERT_NAME_ELEMENT.value = INSERT_NAME_ELEMENT.value.trim();
});
INSERT_USERNAME_ELEMENT.addEventListener("focusout", () => {
    INSERT_USERNAME_ELEMENT.value = INSERT_USERNAME_ELEMENT.value.trim();
});
INSERT_TAGS_ELEMENT.addEventListener("focusout", () => {
    tags = [];

    for(const tag of INSERT_TAGS_ELEMENT.value.split(",")) {
        const trimmed = tag.trim();

        if(trimmed)
            tags.push(trimmed);
    }

    INSERT_TAGS_ELEMENT.value = tags.join(", ");
});
INSERT_PASSWORD_ELEMENT.addEventListener("focusin", () => {
    INSERT_PASSWORD_ELEMENT.select();
});
INSERT_PASSWORD_ELEMENT.addEventListener("focusout", () => {
    INSERT_PASSWORD_ELEMENT.value = INSERT_PASSWORD_ELEMENT.value.trim();
});
INSERT_BUTTON_ELEMENT.addEventListener("mousedown", insertEvent);
COMMIT_BUTTON_ELEMENT.addEventListener("mousedown", async () => {
    await commitEvent();
    getAuthInfoEvent();
});

SEARCH_QUERY_ELEMENT.addEventListener("input", () => {
    searchEvent(SEARCH_QUERY_ELEMENT.value);
});

STORE_ELEMENT.querySelector("thead th#name").addEventListener("mousedown",
    () => {
        if(sortOrder.category != "name")
            sortOrder.category = "name";
        else
            sortOrder.name = !sortOrder.name;
        sortStoreEvent();
    });
STORE_ELEMENT.querySelector("thead th#date").addEventListener("mousedown",
    () => {
        if(sortOrder.category != "date")
            sortOrder.category = "date";
        else
            sortOrder.date = !sortOrder.date;
        sortStoreEvent();
    });
STORE_ELEMENT.querySelector("thead th#username").addEventListener("mousedown",
    () => {
        if(sortOrder.category != "username")
            sortOrder.category = "username";
        else
            sortOrder.username = !sortOrder.username;
        sortStoreEvent();
    });

generator.draw();
store.draw();

STORE_ELEMENT.querySelector("thead th#" + sortOrder.category).classList
    .add("sort");
for(const arrow of STORE_ELEMENT.querySelectorAll("thead th #arrow"))
    arrow.innerText = DOWN_ARROW_SYMBOL;

getAuthInfoEvent();
generateEvent();
