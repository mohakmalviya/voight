import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';

export function webauthn(config) {
  return {
    registrationOptions: (userID, label) => generateRegistrationOptions({
      rpName: 'Voight', rpID: config.rpID, userID: Buffer.from(userID, 'base64url'), userName: label,
      attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    }),
    verifyRegistration: (response, challenge) => verifyRegistrationResponse({
      response, expectedChallenge: challenge, expectedOrigin: config.origin, expectedRPID: config.rpID,
      requireUserVerification: true,
    }),
    authenticationOptions: () => generateAuthenticationOptions({ rpID: config.rpID, userVerification: 'required', allowCredentials: [] }),
    verifyAuthentication: (response, challenge, credential) => verifyAuthenticationResponse({
      response, expectedChallenge: challenge, expectedOrigin: config.origin, expectedRPID: config.rpID,
      credential: { id: credential.id, publicKey: credential.publicKey, counter: credential.counter, transports: credential.transports },
      requireUserVerification: true,
    }),
  };
}
