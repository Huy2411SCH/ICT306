// Creates an admin account with a random one-time master password (no default credentials).
// Usage: npm run create-admin -- <username>
import { randomInt } from 'node:crypto';
import { USERNAME_RE, findUserByName, createUser } from '../src/users.js';

const username = process.argv[2];
if (!username || !USERNAME_RE.test(username)) {
  console.error('Usage: npm run create-admin -- <username>   (3-32 chars: letters, numbers, . _ -)');
  process.exit(1);
}
if (findUserByName.get(username)) {
  console.error(`User "${username}" already exists.`);
  process.exit(1);
}

const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
const password = Array.from({ length: 24 }, () => charset[randomInt(charset.length)]).join('');

await createUser(username, password, 'admin');
console.log(`\nAdmin "${username}" created.`);
console.log(`Master password (shown ONCE, store it safely): ${password}`);
console.log('Log in, set up 2FA, then change this password under Settings.\n');
