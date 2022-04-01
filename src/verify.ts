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
import { verify as jwtVerify } from 'jsonwebtoken';

import type { JWKpem } from '@oada/certs/dist/jwks-utils';
import { jwksUtils as jwks } from '@oada/certs';

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
  const key = jwk.kty === 'PEM' ? (jwk as JWKpem).pem : jwk2pem(jwk as RSA_JWK);

  const verifyOptions = {
    issuer,
    audience: tokenEndpoint,
  };

  const jwtPayload = jwtVerify(token, key, verifyOptions);
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
