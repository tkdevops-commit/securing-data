// Function encrypts data using web API
const generateKey = async () => {
    return crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
};

const encryptData = async (data, key) => {
    const encoded = new TextEncoder().encode(data);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encoded
    );
    return { encrypted, iv };
};

const sanitizeInput = (input) => {
    const element = document.createElement('div');
    element.innerText = input;
    return element.innerHTML;
};

const secureForm = document.getElementById('secureForm');
secureForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const inputData = document.getElementById('inputData').value;
    const sanitizedData = sanitizeInput(inputData);

// Generate encrypt key and data
    const key = await generateKey();
    const encryptedData = await encryptData(sanitizedData, key);

// Store encrypted data in session
    localStorage.setItem('encryptedData', btoa(String.fromCharCode(...new Uint8Array(encryptedData.encrypted))));
    localStorage.setItem('iv', btoa(String.fromCharCode(...new Uint8Array(encryptedData.iv))));
});

// Securing cookies
document.cookie = "sessionId=your-session-id; Secure; HttpOnly";

// CORS request
fetch('https://your-allowed-domain.com/api/data', {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json'
    },
    mode: 'cors',
    credentials: 'include'
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));


// Client-side validation 
function validateForm() {
    let email = document.getElementById('email').value;
    let phone = document.getElementById('phone').value;
    let emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    let phonePattern = /^[0-9]{10}$/;

    if (!emailPattern.test(email)) {
        alert('Please enter a valid email address');
        return false;
    }

    if (!phonePattern.test(phone)) {
        alert('Please enter a valid 10-digit phone number');
        return false;
    }

    return true;
}

document.getElementById('myForm').onsubmit = validateForm;



