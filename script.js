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


// Escaping special cahracters
document.getElementById('myForm').onsubmit = validateForm;

function escapeHtml(text) {
    return text.replace(/[&<>"']/g, function (match) {
        const escapeChars = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escapeChars[match];
    });
}

// Limiting input length 
let userInput = document.getElementById('userInput').value;
let escapedInput = escapeHtml(userInput);
document.getElementById('output').innerText = escapedInput;

document.getElementById('username').addEventListener('input', function() {
    let maxLength = 20;
    if (this.value.length > maxLength) {
        this.value = this.value.slice(0, maxLength);
        alert('Username cannot exceed ' + maxLength + ' characters');
    }
});

const express = require('express');
const helmet = require('helmet');

const app = express();

// Use Helmet to secure HTTP headers
app.use(helmet());

// You can customize Helmet’s behavior by enabling or disabling specific headers
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "trusted-cdn.com"],
            },
        },
        referrerPolicy: { policy: 'no-referrer' },
        xssFilter: true,
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        hsts: {
            maxAge: 31536000, // 1 year
            includeSubDomains: true,
            preload: true,
        },
        noSniff: true,
        ieNoOpen: true,
    })
);

app.get('/', (req, res) => {
    res.send('Hello, world!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


