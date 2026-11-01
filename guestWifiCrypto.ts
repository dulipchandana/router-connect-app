import { AESEncryptionKey } from 'expo-crypto';
import * as forge from 'node-forge';

export interface EncryptedGuestRequest {
  encrypted: '1';
  ct: string;
  ck: string;
}

export interface LoginCryptoValues {
  response: string;
  enckey: string;
  enciv: string;
}

function bytesToBinaryString(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}

function toRouterBase64Url(value: string): string {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '.');
}

function hashBase64(value: string): string {
  const digest = forge.md.sha256.create();
  digest.update(value, 'utf8');
  return forge.util.encode64(digest.digest().getBytes());
}

function hashHex(value: string, encoding: 'raw' | 'utf8'): string {
  const digest = forge.md.sha256.create();
  digest.update(value, encoding);
  return digest.digest().toHex();
}

function toBase64UrlWithoutPadding(value: string): string {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function createLoginCryptoValues(
  username: string,
  password: string,
  salt: string,
  nonce: string,
  iterations: number,
): Promise<LoginCryptoValues> {
  if (!Number.isInteger(iterations) || iterations < 0 || iterations > 10000) {
    throw new Error('The router returned an invalid login iteration count.');
  }

  let passwordHash: string;
  if (iterations >= 1) {
    passwordHash = hashHex(`${salt}${password}`, 'utf8');
    for (let index = 1; index < iterations; index += 1) {
      passwordHash = hashHex(forge.util.hexToBytes(passwordHash), 'raw');
    }
  } else {
    passwordHash = `${salt}${password}`;
  }

  const z = hashBase64(`${username}:${passwordHash.toLowerCase()}`);
  const response = toRouterBase64Url(hashBase64(`${z}:${nonce}`));
  const encryptionKey = await AESEncryptionKey.generate(128);
  const encryptionIv = await AESEncryptionKey.generate(128);
  const encryptionKeyBytes = await encryptionKey.bytes();
  const encryptionIvBytes = await encryptionIv.bytes();

  return {
    response,
    enckey: toRouterBase64Url(
      forge.util.encode64(bytesToBinaryString(encryptionKeyBytes)),
    ),
    enciv: toRouterBase64Url(
      forge.util.encode64(bytesToBinaryString(encryptionIvBytes)),
    ),
  };
}

function createRouterPublicKey(publicKeyValue: string): forge.pki.rsa.PublicKey {
  const publicKey = publicKeyValue
    .replace(/\\r/g, '\r')
    .replace(/\\n/g, '\n')
    .trim();
  if (!publicKey) {
    throw new Error('The cached router public key is empty.');
  }

  if (publicKey.includes('-----BEGIN')) {
    return forge.pki.publicKeyFromPem(publicKey);
  }

  const encodedKey = publicKey
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s/g, '');
  const normalizedBase64 = encodedKey
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/\./g, '=');
  if (!normalizedBase64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(normalizedBase64)) {
    throw new Error('The cached router public key is not PEM or base64-encoded DER.');
  }

  try {
    const publicKeyDer = forge.util.decode64(normalizedBase64);
    return forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(publicKeyDer));
  } catch (error) {
    throw new Error(
      `The cached router public key could not be decoded as PEM or DER: ${
        error instanceof Error ? error.message : 'invalid key data'
      }`,
    );
  }
}

export async function encryptGuestPayload(
  publicKeyValue: string,
  payload: string,
): Promise<EncryptedGuestRequest> {
  const encryptionKey = await AESEncryptionKey.generate(128);
  const encryptionIv = await AESEncryptionKey.generate(128);
  const keyBytes = await encryptionKey.bytes();
  const ivBytes = await encryptionIv.bytes();
  const keyBinary = bytesToBinaryString(keyBytes);
  const ivBinary = bytesToBinaryString(ivBytes);

  const cipher = forge.cipher.createCipher('AES-CBC', keyBinary);
  cipher.start({ iv: ivBinary });
  cipher.update(forge.util.createBuffer(payload, 'utf8'));
  if (!cipher.finish()) {
    throw new Error('AES-CBC encryption of the guest Wi-Fi payload failed.');
  }

  const encryptedKey = createRouterPublicKey(publicKeyValue).encrypt(
    `${forge.util.encode64(keyBinary)} ${forge.util.encode64(ivBinary)}`,
    'RSAES-PKCS1-V1_5',
  );

  return {
    encrypted: '1',
    ct: toBase64UrlWithoutPadding(forge.util.encode64(cipher.output.getBytes())),
    ck: toRouterBase64Url(forge.util.encode64(encryptedKey)),
  };
}
