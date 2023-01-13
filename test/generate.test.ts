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

/* eslint-env mocha */
/* eslint-disable unicorn/prefer-module */

// eslint-disable-next-line @typescript-eslint/no-require-imports
import fs = require('fs');

import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';

import { decode } from 'jws';
import { pem2jwk } from 'pem-jwk';
import { verify } from 'jsonwebtoken';

import type { JWK } from '@oada/certs/dist/jwks-utils';

import { generate } from '../dist';

chai.use(chaiAsPromised);

const { expect } = chai;

describe('generate', () => {
  const privatePem = {
    kid: 'abc123',
    kty: 'PEM',
    // eslint-disable-next-line prefer-template
    pem: fs.readFileSync(__dirname + '/keys/abc123.private.pem').toString(),
  } as const;
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const privateJwk = { ...pem2jwk(privatePem.pem), kid: 'abc123' } as JWK;
  const publicPem = {
    kid: 'abc123',
    kty: 'PEM',
    // eslint-disable-next-line prefer-template
    pem: fs.readFileSync(__dirname + '/keys/abc123.public.pem').toString(),
  } as const;
  const expiresIn = 123;
  const issuer = 'fJd7s723qa';
  const clientId = 'xi7sca3';
  const tokenEndpoint = 'https://example.org/token';

  async function checkToken(token: string) {
    const decoded = decode(token);

    if (decoded.header.kid) {
      expect(decoded.header.kid).to.equal(privatePem.kid);
    }

    expect(decoded.payload.exp - decoded.payload.iat).to.equal(expiresIn);
    expect(decoded.payload.iss).to.equal(issuer);
    expect(decoded.payload.sub).to.equal(clientId);
    expect(decoded.payload.aud).to.equal(tokenEndpoint);

    verify(token, publicPem.pem.toString());
    return decoded;
  }

  it('should require object for key', async () => {
    // @ts-expect-error type intentionally wrong
    const token = generate({});

    await expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should work with a PEM jwk', async () => {
    const token = await generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    await checkToken(token);
  });

  it('should work with an RSA jwk', async () => {
    const token = await generate({
      key: privateJwk,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    await checkToken(token);
  });

  it('should fail if key type not supported', async () => {
    // @ts-expect-error type intentionally wrong
    const token = generate({ key: { kty: '[Unknown]' } });

    await expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require issuer to be a string', async () => {
    const token = generate({
      key: privatePem,
      expiresIn,
      clientId,
      // @ts-expect-error type intentionally wrong
      issuer: undefined,
    });

    await expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require clientId to be a string', async () => {
    const token = generate({
      key: privatePem,
      issuer,
      expiresIn,
      // @ts-expect-error type intentionally wrong
      clientId: undefined,
    });

    await expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require tokenEndpoint to be a string', async () => {
    const token = generate({
      key: privatePem,
      issuer,
      clientId,
      expiresIn,
      // @ts-expect-error type intentionally wrong
      tokenEndpoint: undefined,
    });

    await expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require expires to be a number', async () => {
    const token = generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      // @ts-expect-error type intentionally wrong
      expiresIn: 'expiresIn',
    });

    await expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require options to be an object', async () => {
    const token = generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
      // @ts-expect-error type intentionally wrong
      options: 'options',
    });

    await expect(token).to.eventually.be.rejected;
  });

  it('should not allow overwriting required parameters', async () => {
    const options = {
      algorithm: 'invalid',
      issuer: `${issuer}invalid`,
      subject: `${clientId}invalid`,
      audience: `${tokenEndpoint}invalid`,
      expiresIn: expiresIn + 1000,
    } as const;

    const token = await generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
      options,
    });

    await checkToken(token);
  });

  it('should allow other payload claims', async () => {
    const options = {
      payload: {
        jti: 'JTI',
      },
    };

    const token = await generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
      ...options,
    });

    const decoded = await checkToken(token);
    expect(decoded.payload.jti).to.equal('JTI');
  });

  it('should allow a signing key without an id', async () => {
    const { kid, ...key } = privatePem;
    const token = await generate({
      key,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    const decoded = await checkToken(token);
    expect(decoded.header.kid).to.equal(undefined);
  });
});
