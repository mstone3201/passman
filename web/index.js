async function fetchJSON(url) {
    const response = await fetch(url);
    if(response.ok)
        return await response.json();
    
    throw new Error(url + " not found");
}

const storeElement = document.getElementById("store");

fetchJSON("store").then((store) => {
        console.log(store);
        if(!Array.isArray(store))
            throw new Error("store was invalid");

        for(const entry of store) {
            console.log(entry);
            if(!Object.hasOwn(entry, "id")
                || !Number.isInteger(entry.id)
                || !Object.hasOwn(entry, "ciphertext")
                || typeof entry.ciphertext !== "string")
            {
                throw new Error("entry was invalid in store");
            }

            const entryElement = document.createElement("li");
            entryElement.innerHTML = entry.id + ", " + entry.ciphertext;
            storeElement.appendChild(entryElement);
        }
    }).catch((e) => storeElement.innerHTML =
        "Error loading store");
