import os from 'os';
import path from 'path';

export const WALLET_DATA_DIR = path.join(os.homedir(), '.sparkcli');
export const ENCRYPTED_WALLET_FILE_PATH = path.join(WALLET_DATA_DIR, 'wallet.enc.json');
export const MIN_PASSWORD_LENGTH = 8;

// Crypto constants
export const PBKDF2_ITERATIONS = 100000;
export const KEY_LENGTH = 32; // AES-256
export const SALT_LENGTH = 16;
export const IV_LENGTH = 12; // GCM recommended
export const AUTH_TAG_LENGTH = 16; // GCM default
