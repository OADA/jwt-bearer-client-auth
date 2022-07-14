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

import { pem2jwk } from 'pem-jwk';
import { sign } from 'jsonwebtoken';

import type { JWK } from '@oada/certs/dist/jwks-utils';

import { verify } from '../';

chai.use(chaiAsPromised);

const { expect } = chai;

describe('verify', () => {
  const privatePem = {
    kid: 'abc123',
    kty: 'PEM',
    // eslint-disable-next-line prefer-template, security/detect-non-literal-fs-filename
    pem: fs.readFileSync(__dirname + '/keys/abc123.private.pem').toString(),
  } as const;
  const publicPem = {
    kid: 'abc123',
    kty: 'PEM',
    // eslint-disable-next-line prefer-template, security/detect-non-literal-fs-filename
    pem: fs.readFileSync(__dirname + '/keys/abc123.public.pem').toString(),
  } as const;
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const publicJwk = { ...pem2jwk(publicPem.pem), kid: 'abc123' } as JWK;
  const alg = 'RS256';
  const options = {
    algorithm: alg,
    issuer: 'Xjsi3f93',
    subject: 'vmaAU93F',
    audience: 'https://api.example.org/token',
    expiresIn: 10,
    header: {
      alg,
      kid: privatePem.kid,
    },
  } as const;

  it('should verify a valid token', () => {
    const token = sign({ foo: 'bar' }, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should work with a PEM jwk', () => {
    const token = sign({}, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicPem,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should work with an RSA jwk', () => {
    const token = sign({}, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should require the exp claim', () => {
    const { expiresIn, ...options2 } = options;
    const token = sign({}, privatePem.pem, options2);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should require consistent issuer', () => {
    const token = sign({}, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      clientId: options.subject,
      tokenEndpoint: options.audience,
      issuer: `${options.issuer}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should require consistent subject', () => {
    const token = sign({}, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      tokenEndpoint: options.audience,
      clientId: `${options.subject}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should require consistent audience', () => {
    const token = sign({}, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: `${options.audience}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should enforce not before (nbf) claim', () => {
    const claims = {
      nbf: Math.floor((Date.now() + 10_000) / 1000),
    };

    const token = sign(claims, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should verify external claims', () => {
    const claims = {
      jti: '1234asdf',
    };

    const token = sign(claims, privatePem.pem, options);

    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
      payload: claims,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should require consistent external claims', () => {
    const claims = {
      jti: '1234asdf',
    };

    const token = sign(claims, privatePem.pem, options);

    claims.jti += 'extra';
    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
      payload: claims,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should fail if key type not supported', () => {
    const token = sign({}, privatePem.pem, options);

    // @ts-expect-error type intentionally wrong
    publicJwk.kty = '[Unknown]';
    const valid = verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: `${options.audience}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });
});
