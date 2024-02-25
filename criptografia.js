
const fs = require('fs');
const crypto = require('crypto');

// Paso 2.a: Generar un par de claves pública/privada RSA
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048, // Longitud de la clave
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Guardar las claves en archivos
fs.writeFileSync('public_key.pem', publicKey);
fs.writeFileSync('private_key.pem', privateKey);

// Paso 2.a: Firmar una cadena de texto usando RSA y guardar la firma en un archivo binario B
const nombreCompleto = "Dagmara Grabowska";

const sign = crypto.createSign('RSA-SHA256');
sign.update(nombreCompleto);
const signature = sign.sign(privateKey);

fs.writeFileSync('firma.bin', signature);

// Paso 2.b: Generar una clave secreta de forma segura
const secretKey = crypto.randomBytes(32); // Longitud de la clave en bytes (256 bits)

// Guardar la clave secreta en un archivo
fs.writeFileSync('secret_key.bin', secretKey);

// Paso 2.b: Realizar una operación HMAC sobre una cadena de texto usando SHA256 y guardar el valor hash en un archivo binario C
const hmac = crypto.createHmac('sha256', secretKey);
hmac.update(nombreCompleto);
const hash = hmac.digest();

fs.writeFileSync('hash.bin', hash);

// Paso 2.c: Cargar el archivo binario B y comprobar la firma digital
const loadedSignature = fs.readFileSync('firma.bin');

const verifier = crypto.createVerify('RSA-SHA256');
verifier.update(nombreCompleto);

const verification = verifier.verify(publicKey, loadedSignature);
console.log('La firma es válida:', verification);

// Paso 2.d: Cargar el archivo binario C y comprobar el valor hash
const loadedHash = fs.readFileSync('hash.bin');

const hmacCheck = crypto.createHmac('sha256', secretKey);
hmacCheck.update(nombreCompleto);
const hashCheck = hmacCheck.digest();

const hashVerification = crypto.timingSafeEqual(hashCheck, loadedHash);
console.log('El hash es válido:', hashVerification);
