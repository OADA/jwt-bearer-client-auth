/**
 * @license
 * Copyright 2015 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-disable unicorn/prevent-abbreviations, import/no-commonjs, unicorn/prefer-module */

const webpack = require('webpack');
const puppeteer = require('puppeteer');

process.env.CHROME_BIN = puppeteer.executablePath();

module.exports = function (config) {
  config.set({
    basePath: '',
    plugins: [
      'karma-webpack',
      'karma-mocha',
      'karma-mocha-reporter',
      'karma-firefox-launcher',
      'karma-chrome-launcher',
      'karma-vivaldi-launcher',
    ],
    frameworks: ['mocha', 'webpack'],
    files: ['test/**/*.test.ts'],
    exclude: [],
    preprocessors: {
      'test/**/*.test.ts': ['webpack'],
    },
    karmaTypescriptConfig: {
      bundlerOptions: {
        validateSyntax: false,
      },
      tsconfig: 'test/tsconfig.json',
    },
    webpack: {
      module: {
        rules: [
          {
            test: /\.test\.ts$/,
            use: [
              // Let tests use fs.readFileSync
              {
                loader: 'transform-loader',
                options: 'brfs',
              },
            ],
          },
          {
            test: /\.ts$/,
            loader: 'ts-loader',
          },
        ],
      },
      plugins: [
        new webpack.NormalModuleReplacementPlugin(/node:/, (resource) => {
          resource.request = resource.request.replace(/^node:/, '');
        }),
        new webpack.ProvidePlugin({
          process: require.resolve('process/browser'),
          Buffer: ['buffer', 'Buffer'],
        }),
      ],
      resolve: {
        fallback: {
          buffer: require.resolve('buffer/'),
          crypto: require.resolve('crypto-browserify'),
          util: require.resolve('util/'),
          stream: require.resolve('stream-browserify'),
          url: require.resolve('url/'),
          // eslint-disable-next-line camelcase
          string_decoder: require.resolve('string_decoder/'),
          events: require.resolve('events/'),
          path: require.resolve('path-browserify'),
          assert: require.resolve('assert/'),
          os: require.resolve('os-browserify/browser'),
          module: false,
        },
      },
      context: __dirname,
      node: {
        __dirname: true,
      },
    },
    reporters: ['mocha'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ['ChromeHeadless'],
    singleRun: true,
  });
};
