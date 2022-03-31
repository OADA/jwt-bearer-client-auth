/**
 * @license
 * Copyright 2015 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { RSA_JWK, jwk2pem } from 'pem-jwk';
import jwt from 'jsonwebtoken';

import { jwksUtils as jwks } from '@oada/certs';

export interface GenerateOptions {
  key: jwks.JWKs;
  issuer: string;
  clientId: string;
  tokenEndpoint: string;
  expiresIn: number;
  payload?: Record<string, unknown>;
  options?: { header?: Record<string, unknown> };
}
export async function generate({
  key,
  issuer,
  clientId,
  tokenEndpoint,
  expiresIn,
  payload = {},
  options: { header = {}, ...options } = {},
}: GenerateOptions) {
  // Ensure the required claims are present
  if (
    !jwks.isJWK(key) ||
    typeof issuer !== 'string' ||
    typeof clientId !== 'string' ||
    typeof tokenEndpoint !== 'string' ||
    typeof expiresIn !== 'number'
  ) {
    throw new TypeError('Invalid parameters');
  }

  // Build JWT options
  const jwtOptions: jwt.SignOptions = {
    ...options,
    algorithm: 'RS256',
    issuer,
    subject: clientId,
    audience: tokenEndpoint,
    expiresIn,
    // @ts-expect-error IDEK
    header: {
      // Add keyId if its available
      kid: key.kid,
      ...header,
    },
  };

  const pem = key.kty === 'PEM' ? key.pem! : jwk2pem(key as RSA_JWK);

  return jwt.sign(payload, pem, jwtOptions);
}

export interface VerifyOptions {
  token: string;
  hint: string | false | jwks.JWKs | jwks.JWK;
  issuer: string;
  clientId: string;
  tokenEndpoint: string;
  payload?: Record<string, unknown>;
}
export async function verify({
  token,
  hint,
  issuer,
  clientId,
  tokenEndpoint,
  payload,
}: VerifyOptions) {
  const jwk = await jwks.jwkForSignature(token, hint);
  const key = jwk.kty === 'PEM' ? jwk.pem! : jwk2pem(jwk as RSA_JWK);

  const verifyOptions = {
    issuer,
    audience: tokenEndpoint,
  };

  const jwtPayload = jwt.verify(token, key, verifyOptions);
  if (typeof jwtPayload === 'string') {
    throw new TypeError(`Failed to parse payload: ${jwtPayload}`);
  }

  if (!jwtPayload.exp) {
    throw new Error('exp claim is required');
  }

  // Check required sub key
  if (jwtPayload.sub !== clientId) {
    throw new Error('sub claim is inconsistent with clientId');
  }

  // Check for optional not before property
  if (jwtPayload.nbf && Math.floor(Date.now() / 1000) <= jwtPayload.nbf) {
    throw new Error('nbf claim violated');
  }

  // Check for any other user required claims
  if (typeof payload === 'object') {
    for (const [k, v] of Object.entries(payload)) {
      if (jwtPayload[k] !== v) {
        throw new Error(`${k} claim is inconsistent`);
      }
    }
  }

  return jwtPayload;
}
