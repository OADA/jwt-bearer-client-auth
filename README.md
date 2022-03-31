# jwt-bearer-client-auth

[![npm](https://img.shields.io/npm/v/jwt-bearer-client-auth)](https://www.npmjs.com/package/jwt-bearer-client-auth)
[![Downloads/week](https://img.shields.io/npm/dw/jwt-bearer-client-auth.svg)](https://npmjs.org/package/jwt-bearer-client-auth)
[![Build Status](https://travis-ci.org/OADA/jwt-bearer-client-auth.svg?branch=master)](https://travis-ci.org/OADA/jwt-bearer-client-auth)
[![Coverage Status](https://coveralls.io/repos/OADA/jwt-bearer-client-auth/badge.svg?branch=master)](https://coveralls.io/r/OADA/jwt-bearer-client-auth?branch=master)
[![Dependency Status](https://david-dm.org/oada/jwt-bearer-client-auth.svg)](https://david-dm.org/oada/jwt-bearer-client-auth)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![License](https://img.shields.io/github/license/OADA/jwt-bearer-client-auth)](LICENSE)

Create and verify RS256 based JWT OAUTH-JWT-bearer client authentications.

## Installation

```shell
yarn add jwt-bearer-client-auth
```

## Import Usage

```typescript
import { generate, verify } from 'jwt-bearer-client-auth';
```

## API

### `generate({key, issuer, clientId, tokenEndpoint, expiresIn, payload, options})`

Generate a valid [jwt-bearer][jwt-bearer] client assertion from client details and the
client's private RSA256 key.

#### Parameters

`key` _{PEM JWK}_ The key used to sign the assertion. Currently, the only
supported key type is "PEM JWK". If the JWK has a `kid` property it will be
included in the client assertion header.

`issuer` _{String}_ An "unique identifier for the entity that issued the JWT."
A good choice for a client generating assertions on the fly might be the client's
OAuth 2.0 client ID.

`clientId` _{String}_ The client's OAuth 2.0 client ID. It is the required value
for the JWT's `sub` claim.

`tokenEndpoint` _{String}_ The OAuth 2.0 authorization server's token endpoint.
It is the required value for the JWT's `aud` claim.

`expiresIn` _{Number}_ The number of seconds from now in which the client
assertion expires.

`payload` _{Object}_ The properties of this object will be included in the
JWT's claim body.

`options` _{Object}_ The `options` parameter is passed directly to
[node-jsonwebtoken][auth0/node-jsonwebtoken]. This module will not allow the
caller to override the properties required by the [jwt-bearer][jwt-bearer] RFC.

#### Usage Example

```typescript
// Generate a jwt-bearer client assertion

import fs from 'node:fs/promises';

import { generate } from 'jwt-bearer-client-auth';

const key = {
  kid: 'abc123',
  kty: 'PEM',
  pem: await fs.readFile('abc123.private.pem'),
};
const issuer = 'aksdfj2w3';
const clientId = 'ocjvS38kjxfa3JFXal342';
const tokenEndpoint = 'https://api.example.org/token';
const expiresIn = 60;
const payload: {
  jti: 'zkjfa3i13';
};

const assertion = await generate({
  key,
  issuer,
  clientId,
  tokenEndpoint,
  expiresIn,
  payload,
});
```

### `verify({token, hint, issuer, clientId, tokenEndpoint, payload})`

Verify the given `assertion` is a valid [jwt-bearer][jwt-bearer] client
assertion.

#### Returned Value

A payload promise is returned, but a traditional `function(err, valid)` callback
is also supported.

#### Parameters

`token` _{JWT}_ The token which is being verified as a valid JWT-bearer client
assertion.

`hint` _{JWK/JWKS/JWK URI/false}_ This is passed directly to the
[jwks-utils][jwks-utils] `jwkForSignature` method. It can be:

- The JWK for the token
- A JWKS in which the tokens JWK is stored (by key id, `kid`)
- A URI for a JWKS in which the tokens JWK is stored (by key id, `kid`)
- Or, `false`, indicating that the key is stored within the token's header
  under either the `jwk` or `jku` property (note this can be easily be
  spoofed and the key should be verified by other means before trusting it).

`issuer` _{String}_ An "unique identifier for the entity that issued the JWT."
A good choice for a client generating assertions on the fly might be the client's
OAuth 2.0 client ID.

`clientId` _{String}_ The client's OAuth 2.0 client ID. It is the required value
for the JWT's `sub` claim.

`tokenEndpoint` _{String}_ The OAuth 2.0 authorization server's token endpoint.
It is the required value for the JWT's `aud` claim.

`payload` _{Object}_ Extra payload claims (and acceptable values) the caller
requires to be included in the token to verify the assertion.

#### Usage Example

```typescript
// Verify a jwt-bearer-client-auth client assertion

import { verify } from 'jwt-bearer-client-auth';

const assertion = getClientAssertion();
const key = getPublicKey();
const issuer = getIssuer();
const clientId = getClientId();
const tokenEndpoint = getTokenEndpoint();
const options = {
  jti: 'xjkaf3xz',
};

try {
  const payload = await verify({
    assertion,
    key,
    issuer,
    clientId,
    tokenEndpoint,
    options,
  });
  console.log('Client assertion validated');
} catch (error: unknown) {
  console.error(err, 'Client assertion was not validated');
}
```

[jwt-bearer]: https://tools.ietf.org/id/draft-ietf-oauth-jwt-bearer.txt
[node-jsonwebtoken]: https://github.com/auth0/node-jsonwebtoken
[jwks-utils]: https://github.com/oada/node-jwks-utils
