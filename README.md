[![Build Status](https://travis-ci.org/OADA/jwt-bearer-client-auth.svg?branch=master)](https://travis-ci.org/OADA/jwt-bearer-client-auth)
[![Coverage Status](https://coveralls.io/repos/OADA/jwt-bearer-client-auth/badge.svg?branch=master)](https://coveralls.io/r/OADA/jwt-bearer-client-auth?branch=master)
[![Dependency Status](https://david-dm.org/oada/jwt-bearer-client-auth.svg)](https://david-dm.org/oada/jwt-bearer-client-auth)
[![License](http://img.shields.io/:license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

# jwt-bearer-client-auth #

## Installation ##
```shell
npm install jwt-bearer-client-auth
```

## Require Usage ##
```javascript
var clientAuth = require('jwt-bearer-client-auth');
```

## API ##

### generate() ###
*Still under development.* Generate a valid jwt-bearer-client-auth client
assertion from given client details and key.

#### Parameters ####

#### Usage Example ####
```javascript
// Generate a jwt-bearer-client-auth client assertion
var assertion = clientAuth.generate();
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
