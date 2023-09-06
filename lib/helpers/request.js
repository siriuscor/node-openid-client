const assert = require('assert');
const querystring = require('querystring');
const http = require('http');
const https = require('https');
const http2 = require('http2');
const { once } = require('events');
const { URL } = require('url');

const LRU = require('lru-cache');

const pkg = require('../../package.json');
const { RPError } = require('../errors');

const pick = require('./pick');
const { deep: defaultsDeep } = require('./defaults');
const { HTTP_OPTIONS } = require('./consts');

let DEFAULT_HTTP_OPTIONS;
const NQCHAR = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

const allowed = [
  'agent',
  'ca',
  'cert',
  'crl',
  'headers',
  'key',
  'lookup',
  'passphrase',
  'pfx',
  'timeout',
  'http2',
];

const setDefaults = (props, options) => {
  DEFAULT_HTTP_OPTIONS = defaultsDeep(
    {},
    props.length ? pick(options, ...props) : options,
    DEFAULT_HTTP_OPTIONS,
  );
};

setDefaults([], {
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  timeout: 3500,
});

function send(req, body, contentType) {
  if (req.constructor.name === 'ClientHttp2Stream' && body) {
    req.write(body);
    req.end();
    return
  }
  if (contentType) {
    req.removeHeader('content-type');
    req.setHeader('content-type', contentType);
  }
  if (body) {
    req.removeHeader('content-length');
    req.setHeader('content-length', Buffer.byteLength(body));
    req.write(body);
  }
  req.end();
}

const nonces = new LRU({ max: 100 });

function http2request(url, headers) {
  let client = http2.connect(url.origin);
  let req = client.request(headers);
  req.clientRef = client; // use for close
  return req;
}

async function http2response(req, opts) {
  return new Promise((resolve, reject) => {
      req.on('error', (err) => { reject(err); });
      const parts = [];
      req.on('data', (chunk) => { parts.push(chunk); });
      req.on('end', () => {
        resolve(parts);
        req.close();
        req.clientRef.close();
      });
  });
}

module.exports = async function request(options, { accessToken, mTLS = false, DPoP } = {}) {
  let url;
  try {
    url = new URL(options.url);
    delete options.url;
    assert(/^(https?:)$/.test(url.protocol));
  } catch (err) {
    throw new TypeError('only valid absolute URLs can be requested');
  }
  const optsFn = this[HTTP_OPTIONS];
  let opts = options;

  const nonceKey = `${url.origin}${url.pathname}`;
  if (DPoP && 'dpopProof' in this) {
    opts.headers = opts.headers || {};
    opts.headers.DPoP = await this.dpopProof(
      {
        htu: `${url.origin}${url.pathname}`,
        htm: options.method,
        nonce: nonces.get(nonceKey),
      },
      DPoP,
      accessToken,
    );
  }

  let userOptions;
  if (optsFn) {
    userOptions = pick(
      optsFn.call(this, url, defaultsDeep({}, opts, DEFAULT_HTTP_OPTIONS)),
      ...allowed,
    );
  }
  opts = defaultsDeep({}, userOptions, opts, DEFAULT_HTTP_OPTIONS);

  if (mTLS && !opts.pfx && !(opts.key && opts.cert)) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }

  if (opts.searchParams) {
    for (const [key, value] of Object.entries(opts.searchParams)) {
      url.searchParams.delete(key);
      url.searchParams.set(key, value);
    }
  }

  let responseType;
  let form;
  let json;
  let body;
  ({ form, responseType, json, body, ...opts } = opts);

  for (const [key, value] of Object.entries(opts.headers || {})) {
    if (value === undefined) {
      delete opts.headers[key];
    }
  }

  let response;
  let req;
  if (opts.http2) {
    let headers = Object.assign({
      [http2.constants.HTTP2_HEADER_PATH]: url.pathname,
    }, opts.headers);
    if (json) {
      headers[http2.constants.HTTP2_HEADER_METHOD] = 'POST';
      headers['content-type']= 'application/json';
      headers['content-length']= Buffer.from(JSON.stringify(json)).byteLength;
    } else if (form) {
      headers[http2.constants.HTTP2_HEADER_METHOD] = 'POST';
      headers['content-type']= 'application/x-www-form-urlencoded';
      headers['content-length']= Buffer.from(querystring.stringify(form)).byteLength;
    } else if (body) {
      headers[http2.constants.HTTP2_HEADER_METHOD] = 'POST';
      headers['content-length']= Buffer.from(body).byteLength;
    } else {
    }
    req = http2request(url, headers);
    req.setTimeout(opts.timeout);
  } else {
    req = (url.protocol === 'https:' ? https.request : http.request)(url.href, opts);
  }
  return (async () => {
    if (json) {
      send(req, JSON.stringify(json), 'application/json');
    } else if (form) {
      send(req, querystring.stringify(form), 'application/x-www-form-urlencoded');
    } else if (body) {
      send(req, body);
    } else {
      send(req);
    }

    [response] = await Promise.race([once(req, 'response'), once(req, 'timeout')]);

    // timeout reached
    if (!response) {
      req.destroy();
      throw new RPError(`outgoing request timed out after ${opts.timeout}ms`);
    }

    let parts = [];
    if (opts.http2) {
      response = {headers: response};
      response['statusCode'] = response.headers[':status'];
      parts = await http2response(req, opts);
    } else {
      for await (const part of response) {
        parts.push(part);
      }
    }

    if (parts.length) {
      switch (responseType) {
        case 'json': {
          Object.defineProperty(response, 'body', {
            get() {
              let value = Buffer.concat(parts);
              try {
                value = JSON.parse(value);
              } catch (err) {
                Object.defineProperty(err, 'response', { value: response });
                throw err;
              } finally {
                Object.defineProperty(response, 'body', { value, configurable: true });
              }
              return value;
            },
            configurable: true,
          });
          break;
        }
        case undefined:
        case 'buffer': {
          Object.defineProperty(response, 'body', {
            get() {
              const value = Buffer.concat(parts);
              Object.defineProperty(response, 'body', { value, configurable: true });
              return value;
            },
            configurable: true,
          });
          break;
        }
        default:
          throw new TypeError('unsupported responseType request option');
      }
    }

    return response;
  })()
    .catch((err) => {
      if (response) Object.defineProperty(err, 'response', { value: response });
      throw err;
    })
    .finally(() => {
      const dpopNonce = response && response.headers['dpop-nonce'];
      if (dpopNonce && NQCHAR.test(dpopNonce)) {
        nonces.set(nonceKey, dpopNonce);
      }
    });
};

module.exports.setDefaults = setDefaults.bind(undefined, allowed);
