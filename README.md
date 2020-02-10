[![Build Status](https://travis-ci.org/OADA/jwt-bearer-client-auth.svg?branch=master)](https://travis-ci.org/OADA/jwt-bearer-client-auth)
[![Coverage Status](https://coveralls.io/repos/OADA/jwt-bearer-client-auth/badge.svg?branch=master)](https://coveralls.io/r/OADA/jwt-bearer-client-auth?branch=master)
[![Dependency Status](https://david-dm.org/oada/jwt-bearer-client-auth.svg)](https://david-dm.org/oada/jwt-bearer-client-auth)
[![License](http://img.shields.io/:license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

# jwt-bearer-client-auth #

Create and verify RS256 based JWT oauth-jwt-bearer client authentications.

## Installation ##
```shell
npm install jwt-bearer-client-auth
```

## Require Usage ##
```javascript
var clientAuth = require('jwt-bearer-client-auth');
```

## API ##

### generate(key, issuer, clientId, tokenEndpoint, expiresIn, options) ###
Generate a valid [jwt-bearer][jwt-bearer] client assertion from client details and the
client's private RSA256 key.

#### Parameters ####
`key` *{PEM JWK}* The key used to sign the assertion. Currentlt the only
supported key type is "PEM JWK". If the JWK has a `kid` property it will be
included in the client assertion header.

`issuer` *{String}* An "unique identifier for the entity that issued the JWT." A
good choice for a client generating assertions on-the-fly might be the client's
OAuth 2.0 client ID.

`clientId` *{String}* The client's OAuth 2.0 client ID. It is the required value
for the JWT's `sub` claim.

`tokenEndpoint` *{String}* The OAuth 2.0 authorization server's token endpoint.
It is the required value for the JWT's `aud` claim.

`expiresIn` *{Number}* The number of seconds from now in which the client
assertion expires.

`options` *{Object}* The `options` parameter is passed directly to
[node-jsonwebtoken][auth0/node-jsonwebtoken]. This module will not allow the
caller  to override the properties required by the [jwt-bearer][jwt-bearer] RFC.
You can add properties to the header and claim set with the following
sub-objects:

  * `header` *{Object}* The properties of this object will be included in the
    JWT's header.
  * `payload` *{Object}* The properties of this object will be included in the
    JWT's claim body.

#### Usage Example ####
```javascript
// Generate a jwt-bearer client assertion
var fs = require('fs');

var key = {
  kid: 'abc123',
  kty: 'PEM',
  pem: fs.readFileSync('abc123.private.pem')
};
var issuer = 'aksdfj2w3';
var clientId = 'ocjvS38kjxfa3JFXal342';
var tokenEndpoint = 'https://api.example.org/token';
var expiresIn = 60;
var options = {
  payload: {
    jti: 'zkjfa3i13'
  }
};

var assertion = clientAuth.generate(key, issuer, clientId, tokenEndpoint,
  expiresIn, options);
```

### verify(token, hint, issuer, clientId, tokenEndpoint, options, [cb]) ###
Verify the given `assertion` is a valid [jwt-bearer][jwt-bearer] client
assertion.

#### Returned Value ####
A payload promise is returned, but a traditional `function(err, valid)` callback
is also supported.

#### Parameters ####
`token` *{JWT}* The token which is being verified as a valid jwt-bearer client
assertion.

`hint` *{JWK/JWKS/JWK URI/false}* This is passed directly to the
[jwks-utils][jwks-utils] `jwkForSignature` method. It can be:
  - The JWK for the token
  - A JWKS which the tokens JWK is stored in (by key id, `kid`)
  - A URI for a JWKS which the tokens JWK is stored in (by key id, `kid`)
  - Or, `false`, indicating that the key is stored within the token's header
    under either the `jwk` or `jku` property (note this can be easily be
    spoofed and the key should be verfied by other means before trusting it).

`issuer` *{String}* An "unique identifier for the entity that issued the JWT." A
good choice for a client generating assertions on-the-fly might be the client's
OAuth 2.0 client ID.

`clientId` *{String}* The client's OAuth 2.0 client ID. It is the required value
for the JWT's `sub` claim.

`tokenEndpoint` *{String}* The OAuth 2.0 authorization server's token endpoint.
It is the required value for the JWT's `aud` claim.

`options` *{Object}* The `options` parameter is used to customize the
verification of the client assertion. The properties of this object are:
  * `payload` *{Object}* Extra payload claims (and acceptable values) the caller
    is requiring to be included in the token in order to verify the assertion.

`cb` *{Function}* The `cb(err, payload)` function can be used instead of the
returned promise in the typical node fashion.

#### Usage Example ####
```javascript
// Verify a jwt-bearer-client-auth client assertion
var assertion = getClientAssertion();
var key = getPublicKey();
var issuer = getIssuer();
var clientId = getClientId();
var tokenEndpoint = getTokenEndpoint();
var options = {
  jti: 'xjkaf3xz'
};

clientAuth
  .verify(assertion, key, issuer, clientId, tokenEndpoint, options)
  .then(function(payload) {
    console.log('Client assertion validated');
  })
  .catch(function(err) {
    console.log('Client assertion was not validated, because: ' + err);
  });
})
```

[jwt-bearer]: https://tools.ietf.org/id/draft-ietf-oauth-jwt-bearer.txt
[node-jsonwebtoken]: https://github.com/auth0/node-jsonwebtoken
[jwks-utils]: https://github.com/oada/node-jwks-utils
