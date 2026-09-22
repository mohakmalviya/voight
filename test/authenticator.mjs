// A software authenticator ONLY for tests. Real WebAuthn verification still runs.
import { generateKeyPairSync, randomBytes, createHash, sign } from 'node:crypto';
const hash = value => createHash('sha256').update(value).digest();
const b64 = value => Buffer.from(value).toString('base64url');
function head(major, size) {
  if (size < 24) return Buffer.from([(major << 5) | size]);
  if (size < 256) return Buffer.from([(major << 5) | 24, size]);
  const result = Buffer.alloc(3); result[0] = (major << 5) | 25; result.writeUInt16BE(size, 1); return result;
}
function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error('Unsupported fixture value');
}
export function authenticator(rpID, origin) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' }); const id = randomBytes(32); let counter = 0;
  const key = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  return {
    id: b64(id),
    register(challenge, overrides = {}) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false, ...overrides }));
      const length = Buffer.alloc(2); length.writeUInt16BE(id.length);
      const authData = Buffer.concat([hash(rpID), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, id, key]);
      return { id: b64(id), rawId: b64(id), type: 'public-key', response: { clientDataJSON: b64(clientDataJSON), attestationObject: b64(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))), transports: ['internal'] }, clientExtensionResults: {}, authenticatorAttachment: 'platform' };
    },
    login(challenge, { uv = true, originOverride = origin, userHandle } = {}) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: originOverride, crossOrigin: false }));
      const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
      const authData = Buffer.concat([hash(rpID), Buffer.from([uv ? 5 : 1]), count]);
      return { id: b64(id), rawId: b64(id), type: 'public-key', response: { clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authData), signature: b64(sign('sha256', Buffer.concat([authData, hash(clientDataJSON)]), privateKey)), ...(userHandle ? { userHandle } : {}) }, clientExtensionResults: {}, authenticatorAttachment: 'platform' };
    },
  };
}
