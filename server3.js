const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = 8080;

// Generate an RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

// Convert the RSA components to base64-encoded strings
const modulusBase64 = publicKey
  .split('\n')
  .slice(1, -2) // Remove header and footer
  .join('')
  .replace(/\s/g, ''); // Remove whitespace

const exponentBase64 = 'AQAB'; // Exponent is usually a constant value "AQAB"

// Generate a Key ID (kid)
const keyId = 'my-key-id';

// JWKS endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  const jwk = {
    kid: keyId,
    alg: 'RS256',
    kty: 'RSA',
    use: 'sig',
    n: modulusBase64, // Remove header and footer
    e: exponentBase64 // Exponent value
  };
  res.json({ keys: [jwk] });
});

// Authentication endpoint
app.post('/auth', (req, res) => {
  // Payload for the JWT (you can customize this)
  const payload = {
    sub: '1234567890',
    name: 'John Doe',
    iat: Math.floor(Date.now() / 1000),
  };

  // Define expirationTimestamp within this scope
  const expirationTimestamp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

  // Check if the 'expired' query parameter is present and equals 'true'
  if (req.query.expired === 'true') {
    // Use the expired key and timestamp
    payload.exp = expirationTimestamp - 3600; // Set it to one hour ago
  } else {
    // Use the current key and timestamp
    payload.exp = expirationTimestamp;
  }

  // Sign the JWT with the private key
  //const token = jwt.sign(payload, privateKey, {
  // algorithm: 'RS256',
  // keyid: keyId,  
  // });

  // Sign the JWT with the private key and specify the header
  const token = jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    keyid: keyId,
    header: {
      kid: keyId,
      alg: 'RS256',
      kty: 'RSA',
      use: 'sig',
      n: modulusBase64, // Remove header and footer
      e: exponentBase64, // Exponent value
    },
  });

  const decodedHeader = jwt.decode(token, { complete: true });
  console.log('Decoded JWT Header:', decodedHeader.header);

  res.status(200).send(token);
});

// Start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
