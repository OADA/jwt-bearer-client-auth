/* Copyright 2015 Open Ag Data Alliance
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

'use strict'

var objectAssign = require('object-assign')
var Promise = require('bluebird')
Promise.longStackTraces()
var jwt = Promise.promisifyAll(require('jsonwebtoken'))
var jwks = require('@oada/oada-certs').jwksutils
var jwk2pem = require('pem-jwk').jwk2pem

function generate (key, issuer, clientId, tokenEndpoint, expiresIn, options) {
  // Ensure the required claims are present
  if (
    !jwks.isJWK(key) ||
    typeof issuer !== 'string' ||
    typeof clientId !== 'string' ||
    typeof tokenEndpoint !== 'string' ||
    typeof expiresIn !== 'number' ||
    (options && typeof options !== 'object')
  ) {
    return undefined
  }

  // Built JWT options
  options = options || {}
  var payload = options.payload || {}
  delete options.payload
  objectAssign(options, {
    algorithm: 'RS256',
    issuer: issuer,
    subject: clientId,
    audience: tokenEndpoint,
    expiresIn: expiresIn
  })

  // Add keyId if its available
  if (key.kid) {
    objectAssign(options, {
      header: {
        kid: key.kid
      }
    })
  }

  var pem = key.kty === 'PEM' ? key.pem : jwk2pem(key)

  return jwt.sign(payload, pem, options)
}

function verify (token, hint, issuer, clientId, tokenEndpoint, options, cb) {
  options = options || {}

  return jwks
    .jwkForSignature(token, hint)
    .then(function (jwk) {
      var key = jwk.kty === 'PEM' ? jwk.pem : jwk2pem(jwk)

      var verifyOpts = {
        issuer: issuer,
        audience: tokenEndpoint
      }

      return jwt.verifyAsync(token, key, verifyOpts).then(function (payload) {
        // Verify the exp is present (jwt verified it's value if it is)
        if (!payload.exp) {
          throw new Error('exp claim is required')
        }

        // Check required sub key
        if (payload.sub !== clientId) {
          throw new Error('sub claim is inconsistent with clientId')
        }

        // Check for optional not before property
        if (payload.nbf && Math.floor(Date.now() / 1000) <= payload.nbf) {
          throw new Error('nbf claim violated')
        }

        // Check for any other user required claims
        if (typeof options.payload === 'object') {
          var keys = Object.keys(options.payload)

          for (var i = 0; i < keys.length; i++) {
            if (payload[keys[i]] !== options.payload[keys[i]]) {
              throw new Error(keys[i] + ' claim is inconsistent')
            }
          }
        }

        return payload
      })
    })
    .nodeify(cb)
}

module.exports.generate = generate
module.exports.verify = verify
