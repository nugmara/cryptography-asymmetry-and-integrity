const fs = require('fs');
const crypto = require('crypto');

// Verificar si los archivos existen antes de generarlos
if (!fs.existsSync('public_key.pem') || !fs.existsSync('private_key.pem')) {
    // Generar las claves RSA y guardarlas en archivos solo si no existen
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
}

// Verificar si la firma existe
let loadedSignature;
if (fs.existsSync('firma.bin')) {
    // Cargar la firma desde el archivo
    loadedSignature = fs.readFileSync('firma.bin');
} else {
    // Firmar la cadena de texto usando RSA y guardar la firma en un archivo binario B solo si no existe
    const nombreCompleto = "Dagmara Grabowska";
    const privateKey = fs.readFileSync('private_key.pem'); // Se carga la clave privada aquí
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(nombreCompleto);
    loadedSignature = sign.sign(privateKey);
    fs.writeFileSync('firma.bin', loadedSignature);
}

// Continuar con el resto del código después de verificar la existencia de las claves
// Paso 2.b: Generar una clave secreta de forma segura
if (!fs.existsSync('secret_key.bin')) {
    // Generar la clave secreta solo si no existe
    const secretKey = crypto.randomBytes(32); // Longitud de la clave en bytes (256 bits)

    // Guardar la clave secreta en un archivo
    fs.writeFileSync('secret_key.bin', secretKey);
}

// Paso 2.b: Realizar una operación HMAC sobre una cadena de texto usando SHA256 y guardar el valor hash en un archivo binario C
if (!fs.existsSync('hash.bin')) {
    // Realizar la operación HMAC solo si el archivo no existe
    const secretKey = fs.readFileSync('secret_key.bin');
    const nombreCompleto = "Dagmara Grabowska"; // Mueve esta línea aquí

    const hmac = crypto.createHmac('sha256', secretKey);
    hmac.update(nombreCompleto);
    const hash = hmac.digest();

    fs.writeFileSync('hash.bin', hash);
}

// Paso 2.c: Cargar el archivo binario B y comprobar la firma digital
// const loadedSignature = fs.readFileSync('firma.bin'); // Esta línea ya no es necesaria aquí

const publicKey = fs.readFileSync('public_key.pem');

const verifier = crypto.createVerify('RSA-SHA256');
const nombreCompleto = "Dagmara Grabowska"; // Mueve esta línea aquí
verifier.update(nombreCompleto); // Cambia esto a "Dagmara Grabowska" si es necesario

const verification = verifier.verify(publicKey, loadedSignature);
console.log('La firma es válida:', verification);
console.log('Firma cargada:', loadedSignature.toString('hex'));

// Paso 2.d: Cargar el archivo binario C y comprobar el valor hash
const loadedHash = fs.readFileSync('hash.bin');

const secretKey = fs.readFileSync('secret_key.bin');

const hmacCheck = crypto.createHmac('sha256', secretKey);
hmacCheck.update(nombreCompleto); // Utiliza la variable aquí
const hashCheck = hmacCheck.digest();

const hashVerification = crypto.timingSafeEqual(hashCheck, loadedHash);
console.log('El hash es válido:', hashVerification);
