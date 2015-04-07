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

var fs = require('fs');
var expect = require('chai').expect;
var jws = require('jws');
var jwt = require('jsonwebtoken');
var clientAuth = require('../');

describe('exports', function() {
    ['generate', 'verify'].forEach(function(method) {
        it('should export ' + method, function() {
            expect(clientAuth[method]).to.be.a('function');
        });
    });
});

describe('generate', function() {
    var privatePem;
    var publicPem;
    var expiresIn;
    var issuer;
    var clientId;
    var tokenEndpoint;

    function checkToken(token, cb) {
        var decoded = jws.decode(token);
        expect(decoded.header.kid).to.equal(privatePem.kid);
        expect(decoded.payload.exp - decoded.payload.iat).to.equal(expiresIn);
        expect(decoded.payload.iss).to.equal(issuer);
        expect(decoded.payload.sub).to.equal(clientId);
        expect(decoded.payload.aud).to.equal(tokenEndpoint);

        jwt.verify(token, publicPem.toString(), function(err) {
            expect(err).to.not.be.ok;

            cb(decoded);
        });
    }

    beforeEach(function() {
        expiresIn = 123;
        issuer = 'fJd7s723qa';
        clientId = 'xi7sca3';
        tokenEndpoint = 'https://example.org/token';
        privatePem = {
            kid: 'abc123',
            kty: 'PEM',
            pem: fs.readFileSync('test/keys/abc123.private.pem')
        };

        publicPem = fs.readFileSync('test/keys/abc123.public.pem');
    });

    it('should require object for key', function() {
        var token = clientAuth.generate();

        expect(token).to.equal(undefined);
    });

    it('should require a PEM key', function() {
        var token = clientAuth.generate({kty: 'RSA'});

        expect(token).to.equal(undefined);
    });

    it('should require issuer to be a string', function() {
        var token = clientAuth.generate(privatePem, expiresIn);

        expect(token).to.equal(undefined);
    });

    it('should require clientId to be a string', function() {
        var token = clientAuth.generate(privatePem, issuer, expiresIn);

        expect(token).to.equal(undefined);
    });

    it('should require tokenEndpoint to be a string', function() {
        var token = clientAuth.generate(privatePem, issuer, clientId,
            expiresIn);

        expect(token).to.equal(undefined);
    });

    it('should require expires to be a number', function() {
        var token = clientAuth.generate(privatePem, issuer, clientId,
            tokenEndpoint, 'expiresIn');

        expect(token).to.equal(undefined);
    });

    it('should require options to be an object', function() {
        var token = clientAuth.generate(privatePem, issuer, clientId,
            tokenEndpoint, expiresIn, 'options');

        expect(token).to.equal(undefined);
    });

    it('should allow no options', function(done) {
        var token = clientAuth.generate(privatePem, issuer, clientId,
            tokenEndpoint, expiresIn);

        checkToken(token, function() {
            done();
        });
    });

    it('should not allow overwriting required parameters', function(done) {
        var options = {
            algorithm: 'RS256' + 'invalid',
            issuer: issuer + 'invalid',
            subject: clientId + 'invalid',
            audience: tokenEndpoint + 'invalid',
            expiresInSeconds: expiresIn + 1000
        };

        var token = clientAuth.generate(privatePem, issuer, clientId,
            tokenEndpoint, expiresIn, options);

        checkToken(token, function() {
            done();
        });
    });

    it('should allow other payload claims', function(done) {
        var options = {
            payload: {
                jti: 'JTI'
            }
        };

        var token = clientAuth.generate(privatePem, issuer, clientId,
            tokenEndpoint, expiresIn, options);

        checkToken(token, function(decoded) {
            expect(decoded.payload.jti).to.equal('JTI');

            done();
        });
    });

    it('should allow a signing key with an id', function(done) {
        delete privatePem.kid;

        var token = clientAuth.generate(privatePem, issuer, clientId,
            tokenEndpoint, expiresIn);

        checkToken(token, function(decoded) {
            expect(decoded.header.kid).to.equal(undefined);

            done();
        });
    });
});
