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
'use strict';

var objectAssign = require('object-assign');
var jwt = require('jsonwebtoken');

function generate(key, issuer, clientId, tokenEndpoint, expiresIn, options) {
    // Ensure the required claims are present
    if (typeof key !== 'object' || key.kty !== 'PEM' ||
        typeof issuer !== 'string' ||
        typeof clientId !== 'string' ||
        typeof tokenEndpoint !== 'string' ||
        typeof expiresIn !== 'number' ||
        (options && typeof options !== 'object')) {

        return undefined;
    }

    // Built JWT options
    options = options || {};
    options.payload = options.payload || {};
    objectAssign(options, {
        algorithm: 'RS256',
        issuer: issuer,
        subject: clientId,
        audience: tokenEndpoint,
        expiresInSeconds: expiresIn
    });

    // Add keyId if its available
    if (key.kid) {
        objectAssign(options, {
            headers: {
                kid: key.kid
            }
        });
    }

    return jwt.sign(options.payload, key.pem, options);
}

function verify() {

}

module.exports.generate = generate;
module.exports.verify = verify;
