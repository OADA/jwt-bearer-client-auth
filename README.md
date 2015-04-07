[![Build Status](https://travis-ci.org/OADA/jwt-bearer-client-auth.svg?branch=master)](https://travis-ci.org/OADA/jwt-bearer-client-auth)
[![Coverage Status](https://coveralls.io/repos/OADA/jwt-bearer-client-auth/badge.svg?branch=master)](https://coveralls.io/r/OADA/jwt-bearer-client-auth?branch=master)
[![Dependency Status](https://david-dm.org/oada/jwt-bearer-client-auth.svg)](https://david-dm.org/oada/jwt-bearer-client-auth)
[![License](http://img.shields.io/:license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

# jwt-bearer-client-auth #

Create and verify RS256 based JWT oauth-jwt-beaeer client authentications.

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
Generate a valid jwt-bearer-client-auth client assertion from client details and
the client's private RSA256 key.

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
caller  to override the properties required by the jwt-bearer-client-auth RFC.
You can add properties to the header and claim set with the following
sub-objects:

  * `headers` *{Object}* The properties of this object will be included in the
    JWT's header.
  * `payload` *{Object}* The properties of this object will be included in the
    JWT's claim body.

#### Usage Example ####
```javascript
// Generate a jwt-bearer-client-auth client assertion
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

### verify(assertion) ###
*Still under development.* Verify the given `assertion` is a valid
jwt-bearer-client-auth client assertion.

#### Parameters ####
`assertion` the jwt-bearer-auth client assertion in question.

#### Usage Example ####
```javascript
// Verify a jwt-bearer-client-auth client assertion
if(clientAuth.verify(assertion), function(err, valid) {
  if(valid) {
    // Approve OAuth 2.0 request
  }
})
```

[jwt-bearer-client-auth]:
[node-jsonwebtoken]: https://github.com/auth0/node-jsonwebtoken
