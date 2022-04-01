/**
 * @license
 * Copyright 2015-2022 Open Ag Data Alliance
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
import { SignOptions, sign } from 'jsonwebtoken';

import type { JWKpem } from '@oada/certs/dist/jwks-utils';
import { jwksUtils as jwks } from '@oada/certs';

/**
 * Ensure all required claims are present
 */
function checkClaims({
  key,
  issuer,
  clientId,
  tokenEndpoint,
  expiresIn,
}: GenerateOptions) {
  // Ensure the required claims are present
  if (!jwks.isJWK(key)) {
    throw new TypeError('key must be a JWK');
  }

  if (typeof issuer !== 'string') {
    throw new TypeError('issuer must be a string');
  }

  if (typeof clientId !== 'string') {
    throw new TypeError('clientId must be a string');
  }

  if (typeof tokenEndpoint !== 'string') {
    throw new TypeError('tokenEndpoint must be a string');
  }

  if (typeof expiresIn !== 'number') {
    throw new TypeError('expiresIn must be a number');
  }
}

export interface GenerateOptions {
  key: jwks.JWK;
  issuer: string;
  clientId: string;
  tokenEndpoint: string;
  expiresIn: number;
  payload?: string | Record<string, unknown>;
  options?: { [key: string]: unknown; header?: Record<string, unknown> };
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
  checkClaims({ key, issuer, clientId, tokenEndpoint, expiresIn });

  // Build JWT options
  const jwtOptions: SignOptions = {
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

  const pem = key.kty === 'PEM' ? (key as JWKpem).pem : jwk2pem(key as RSA_JWK);

  return sign(payload, pem, jwtOptions);
}
