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
/* eslint-disable import/no-commonjs, unicorn/prefer-module */

const fs = require('fs');

const chai = require('chai');
chai.use(require('chai-as-promised'));
const { expect } = chai;

const jws = require('jws');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');

const clientAuth = require('../');

describe('generate', () => {
  let privatePem;
  let privateJwk;
  let publicPem;
  let publicJwk;
  let expiresIn;
  let issuer;
  let clientId;
  let tokenEndpoint;

  async function checkToken(token) {
    const decoded = jws.decode(token);
    expect(decoded.header.kid).to.equal(privatePem.kid);
    expect(decoded.payload.exp - decoded.payload.iat).to.equal(expiresIn);
    expect(decoded.payload.iss).to.equal(issuer);
    expect(decoded.payload.sub).to.equal(clientId);
    expect(decoded.payload.aud).to.equal(tokenEndpoint);

    await jwt.verify(token, publicPem.pem);
    return decoded;
  }

  beforeEach(() => {
    privatePem = {
      kid: 'abc123',
      kty: 'PEM',
      pem: fs.readFileSync(__dirname + '/keys/abc123.private.pem'),
    };
    privateJwk = pem2jwk(privatePem.pem);
    privateJwk.kid = 'abc123';
    publicPem = {
      kid: 'abc123',
      kty: 'PEM',
      pem: fs.readFileSync(__dirname + '/keys/abc123.public.pem'),
    };
    publicJwk = pem2jwk(publicPem.pem);
    publicJwk.kid = 'abc123';
    expiresIn = 123;
    issuer = 'fJd7s723qa';
    clientId = 'xi7sca3';
    tokenEndpoint = 'https://example.org/token';
  });

  it('should require object for key', async () => {
    const token = clientAuth.generate({});

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should work with a PEM jwk', async () => {
    const token = await clientAuth.generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    await checkToken(token);
  });

  it('should work with an RSA jwk', async () => {
    const token = await clientAuth.generate({
      key: privateJwk,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    await checkToken(token);
  });

  it('should fail if key type not supported', async () => {
    const token = clientAuth.generate({ key: { kty: '[Unknown]' } });

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require issuer to be a string', async () => {
    const token = clientAuth.generate({ key: privatePem, expiresIn });

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require clientId to be a string', async () => {
    const token = clientAuth.generate({
      key: privatePem,
      issuer,
      expiresIn,
    });

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require tokenEndpoint to be a string', async () => {
    const token = clientAuth.generate({
      key: privatePem,
      issuer,
      clientId,
      expiresIn,
    });

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require expires to be a number', async () => {
    const token = clientAuth.generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn: 'expiresIn',
    });

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should require options to be an object', async () => {
    const token = clientAuth.generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
      options: 'options',
    });

    expect(token).to.eventually.be.rejectedWith(TypeError);
  });

  it('should allow no options', async () => {
    const token = await clientAuth.generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    await checkToken(token);
  });

  it('should not allow overwriting required parameters', async () => {
    const options = {
      algorithm: 'RS256' + 'invalid',
      issuer: `${issuer}invalid`,
      subject: `${clientId}invalid`,
      audience: `${tokenEndpoint}invalid`,
      expiresIn: expiresIn + 1000,
    };

    const token = await clientAuth.generate({
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

    const token = await clientAuth.generate({
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
    delete privatePem.kid;

    const token = await clientAuth.generate({
      key: privatePem,
      issuer,
      clientId,
      tokenEndpoint,
      expiresIn,
    });

    const decoded = await checkToken(token);
    expect(decoded.header.kid).to.equal(undefined);
  });
});

describe('verify', () => {
  const privatePem = {
    kid: 'abc123',
    kty: 'PEM',
    pem: fs.readFileSync(__dirname + '/keys/abc123.private.pem'),
  };
  const publicPem = {
    kid: 'abc123',
    kty: 'PEM',
    pem: fs.readFileSync(__dirname + '/keys/abc123.public.pem'),
  };
  const publicJwk = pem2jwk(publicPem.pem);
  publicJwk.kid = 'abc123';
  let options;

  beforeEach(() => {
    options = {
      algorithm: 'RS256',
      issuer: 'Xjsi3f93',
      subject: 'vmaAU93F',
      audience: 'https://api.example.org/token',
      expiresIn: 10,
      header: {
        kid: privatePem.kid,
      },
    };
  });

  it('should verify a valid token', () => {
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should work with a PEM jwk', () => {
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
      token,
      hint: publicPem,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should work with an RSA jwk', () => {
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.ok;
  });

  it('should require the exp claim', () => {
    delete options.expiresIn;
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: options.audience,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should require consistent issuer', () => {
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
      token,
      hint: publicJwk,
      clientId: options.subject,
      tokenEndpoint: options.audience,
      issuer: `${options.issuer}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should require consistent subject', () => {
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      tokenEndpoint: options.audience,
      clientId: `${options.subject}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });

  it('should require consistent audience', () => {
    const token = jwt.sign({}, privatePem.pem, options);

    const valid = clientAuth.verify({
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

    const token = jwt.sign(claims, privatePem.pem, options);

    const valid = clientAuth.verify({
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

    const token = jwt.sign(claims, privatePem.pem, options);

    const valid = clientAuth.verify({
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

    const token = jwt.sign(claims, privatePem.pem, options);

    claims.jti += 'extra';
    const valid = clientAuth.verify({
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
    const token = jwt.sign({}, privatePem.pem, options);

    publicJwk.kty = '[Unknown]';
    const valid = clientAuth.verify({
      token,
      hint: publicJwk,
      issuer: options.issuer,
      clientId: options.subject,
      tokenEndpoint: `${options.audience}extra`,
    });

    return expect(valid).to.eventually.be.rejected;
  });
});
