async function fetchContents(url) {
    const response = await fetch(url);
    if(response.ok)
        return await response.text();
    
    throw new Error(url + " not found");
}

try {
    fetchContents("test").then((contents) =>
        document.getElementById("test").innerText = contents);
} catch(error) {
    console.error(error);
};
