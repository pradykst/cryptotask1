const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const cors = require('cors')
const app = express();
app.use(cors());
const port = 3000;

// Middleware for file upload
const upload = multer({ dest: 'uploads/' });

// Generate keys (should be done once and stored)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Endpoint to sign a file
app.post('/sign', upload.single('file'), (req, res) => {
    const fileBuffer = fs.readFileSync(req.file.path);
    const sign = crypto.createSign('SHA256');
    sign.update(fileBuffer);
    const signature = sign.sign(privateKey, 'hex');
    res.send({ signature });
});

// Endpoint to verify a file's signature
app.post('/verify', upload.fields([{ name: 'file' }, { name: 'signature' }]), (req, res) => {
    const fileBuffer = fs.readFileSync(req.files.file[0].path);
    const signature = fs.readFileSync(req.files.signature[0].path, 'utf8');
    const verify = crypto.createVerify('SHA256');
    verify.update(fileBuffer);
    const isValid = verify.verify(publicKey, signature, 'hex');
    res.send({ isValid });
});

app.listen(port, () => console.log(`Server running on port ${port}`));