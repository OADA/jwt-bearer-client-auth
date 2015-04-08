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

var chai = require('chai');
chai.use(require('chai-as-promised'));
var expect = chai.expect;

var fs = require('fs');
var jws = require('jws');
var jwt = require('jsonwebtoken');
var rsaPemToJwk = require('rsa-pem-to-jwk');
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
    var publicJwk;
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
        privatePem = {
            kid: 'abc123',
            kty: 'PEM',
            pem: fs.readFileSync('test/keys/abc123.private.pem')
        };
        publicPem = fs.readFileSync('test/keys/abc123.public.pem');
        publicJwk = rsaPemToJwk(publicPem, {kid: 'abc123'});
        expiresIn = 123;
        issuer = 'fJd7s723qa';
        clientId = 'xi7sca3';
        tokenEndpoint = 'https://example.org/token';
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

describe('verify', function() {
    var privatePem = {
        kid: 'abc123',
        kty: 'PEM',
        pem: fs.readFileSync('test/keys/abc123.private.pem')
    };
    var publicPem = fs.readFileSync('test/keys/abc123.public.pem');
    var publicJwk = rsaPemToJwk(publicPem, {kid: 'abc123'});
    var options;

    beforeEach(function() {
        options = {
            algorithm: 'RS256',
            issuer: 'Xjsi3f93',
            subject: 'vmaAU93F',
            audience: 'https://api.example.org/token',
            expiresInSeconds: 10,
            headers: {
                kid: privatePem.kid
            }
        };
    });

    it('should verify a valid token', function() {
        var token = jwt.sign({}, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience);

        return expect(valid).to.eventually.be.ok;
    });

    it('should require the exp claim', function() {
        delete options.expiresInSeconds;
        var token = jwt.sign({}, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience);

        return expect(valid).to.eventually.be.rejected;
    });

    it('should require consistent issuer', function() {
        var token = jwt.sign({}, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer + 'extra',
                    options.subject,
                    options.audience);

        return expect(valid).to.eventually.be.rejected;
    });

    it('should require consistent subject', function() {
        var token = jwt.sign({}, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject + 'extra',
                    options.audience);

        return expect(valid).to.eventually.be.rejected;
    });

    it('should require consistent audience', function() {
        var token = jwt.sign({}, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience + 'extra');

        return expect(valid).to.eventually.be.rejected;
    });

    it('should enfore not before (nbf) claim', function() {
        var claims = {
            nbf: Math.floor((Date.now() + 10000) / 1000)
        };

        var token = jwt.sign(claims, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience);

        return expect(valid).to.eventually.be.rejected;
    });

    it('should verify external claims', function() {
        var claims = {
            jti: '1234asdf'
        };

        var token = jwt.sign(claims, privatePem.pem, options);

        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience,
                    {payload: claims});

        return expect(valid).to.eventually.be.ok;
    });

    it('should require consistent external claims', function() {
        var claims = {
            jti: '1234asdf'
        };

        var token = jwt.sign(claims, privatePem.pem, options);

        claims.jti += 'extra';
        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience,
                    {payload: claims});

        return expect(valid).to.eventually.be.rejected;
    });

    it('should fail if key type not supported', function() {
        var token = jwt.sign({}, privatePem.pem, options);

        publicJwk.kty = '[Unknown]';
        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience + 'extra');

        return expect(valid).to.eventually.be.rejected;
    });

    it('should fail if key type not supported', function() {
        var token = jwt.sign({}, privatePem.pem, options);

        publicJwk.kty = '[Unknown]';
        var valid = clientAuth
            .verify(token,
                    publicJwk,
                    options.issuer,
                    options.subject,
                    options.audience + 'extra');

        return expect(valid).to.eventually.be.rejected;
    });

});
