const http = require('node:http');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const wifiLoginCollection = require('./wifi-login.json');
const saltCollection = require('./wifi-log-salt.json');
const postmanHashCollection = require('./postman-hash.json');
const checkExpireCollection = require('./chek-cgi.json');
const wifiStatusCollection = require('./postman-wifi-status.json');
const credentials = require('./router-credentials.local.json');

const nonceRequest = wifiLoginCollection.item[0]?.request;
const saltRequest = saltCollection.item[0]?.request;
const loginRequest = postmanHashCollection.item.find(
  (item) => item.name === 'login_web_app.cgi',
)?.request;
const checkExpireRequest = checkExpireCollection.item[0]?.request;
const wifiOnRequest = require('./wifi-on.json').item[0]?.request;
const guestWifiStatusRequest = wifiStatusCollection.item[0]?.request;
const usernameField = nonceRequest?.body.urlencoded.find(
  (field) => field.key === 'userName',
);

if (
  !nonceRequest?.url.raw ||
  !saltRequest?.url.raw ||
  !loginRequest?.url.raw ||
  !checkExpireRequest?.url.raw ||
  !wifiOnRequest?.url.raw ||
  !guestWifiStatusRequest?.url?.raw ||
  guestWifiStatusRequest.method !== 'GET' ||
  !loginRequest.body?.urlencoded ||
  !wifiOnRequest.body?.urlencoded ||
  !usernameField?.value
) {
  throw new Error('Login request configuration is missing a required URL or username.');
}

const routerUrl = new URL(nonceRequest.url.raw);
const expectedBody = `${encodeURIComponent(usernameField.key)}=${encodeURIComponent(
  usernameField.value,
)}`;
const allowedOrigins = new Set(
  (process.env.EXPO_WEB_ORIGIN ?? 'http://localhost:8081,http://127.0.0.1:8081')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
);
const port = Number(process.env.ROUTER_PROXY_PORT ?? 3001);
const maxBodyBytes = 4096;
const routerCookies = new Map();

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
  });
  response.end(JSON.stringify(body));
}

function hashBase64(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('base64');
}

function toRouterBase64Url(value) {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '.');
}

function updateRouterCookies(setCookieHeaders = []) {
  for (const header of setCookieHeaders) {
    const [cookiePair, ...attributes] = header.split(';');
    const separatorIndex = cookiePair.indexOf('=');
    if (separatorIndex <= 0) {
      continue;
    }

    const name = cookiePair.slice(0, separatorIndex).trim();
    const value = cookiePair.slice(separatorIndex + 1).trim();
    const isExpired = attributes.some((attribute) => {
      const [key, attributeValue] = attribute.trim().split('=');
      if (key.toLowerCase() === 'max-age') {
        return Number(attributeValue) <= 0;
      }
      if (key.toLowerCase() === 'expires') {
        return Date.parse(attributeValue) <= Date.now();
      }
      return false;
    });

    if (!value || isExpired) {
      routerCookies.delete(name);
    } else {
      routerCookies.set(name, value);
    }
  }
}

function cookieHeaderWithSessionId(requestConfig, sid) {
  const configuredCookie = (requestConfig.header ?? []).find(
    (header) => header.key.toLowerCase() === 'cookie',
  )?.value;
  const cookies = (configuredCookie ?? '')
    .split(';')
    .map((cookie) => cookie.trim())
    .filter(Boolean);
  let replacedSid = false;

  const updatedCookies = cookies.map((cookie) => {
    const separatorIndex = cookie.indexOf('=');
    if (
      separatorIndex > 0 &&
      cookie.slice(0, separatorIndex).trim().toLowerCase() === 'sid'
    ) {
      replacedSid = true;
      return `sid=${sid}`;
    }
    return cookie;
  });

  if (!replacedSid) {
    updatedCookies.push(`sid=${sid}`);
  }

  return updatedCookies.join('; ');
}

function calculateResponse(salt, nonce, iterations) {
  if (typeof credentials.username !== 'string' || !credentials.username) {
    throw new Error(
      'Set your router username in router-credentials.local.json, then restart the proxy.',
    );
  }

  if (typeof credentials.password !== 'string' || !credentials.password) {
    throw new Error(
      'Set your router password in router-credentials.local.json, then restart the proxy.',
    );
  }

  let passwordHash;
  if (iterations >= 1) {
    passwordHash = crypto
      .createHash('sha256')
      .update(salt + credentials.password, 'utf8')
      .digest('hex');

    for (let index = 1; index < iterations; index += 1) {
      passwordHash = crypto
        .createHash('sha256')
        .update(Buffer.from(passwordHash, 'hex'))
        .digest('hex');
    }
  } else {
    passwordHash = salt + credentials.password;
  }

  const z = hashBase64(
    `${credentials.username}:${passwordHash.toLowerCase()}`,
  );
  return toRouterBase64Url(hashBase64(`${z}:${nonce}`));
}

function forwardRequest(requestConfig, body, origin, response, cookieOverride) {
  const endpointUrl = new URL(requestConfig.url.raw);
  const headers = (requestConfig.header ?? []).reduce(
    (requestHeaders, header) => {
      const key = header.key.toLowerCase();
      if (!['connection', 'cookie', 'origin', 'referer', 'host'].includes(key)) {
        requestHeaders[header.key] = header.value;
      }
      return requestHeaders;
    },
    {},
  );
  headers.Origin = endpointUrl.origin;
  headers.Referer = `${endpointUrl.origin}/`;
  headers['Content-Type'] = 'application/x-www-form-urlencoded';
  headers['Content-Length'] = Buffer.byteLength(body);
  if (cookieOverride) {
    headers.Cookie = cookieOverride;
  } else if (routerCookies.size > 0) {
    headers.Cookie = Array.from(
      routerCookies,
      ([name, value]) => `${name}=${value}`,
    ).join('; ');
  }

  const upstream = http.request(
    {
      hostname: endpointUrl.hostname,
      port: endpointUrl.port || 80,
      path: `${endpointUrl.pathname}${endpointUrl.search}`,
      method: requestConfig.method,
      headers,
      timeout: 5000,
    },
    (routerResponse) => {
      const responseChunks = [];
      updateRouterCookies(routerResponse.headers['set-cookie']);
      routerResponse.on('data', (chunk) => responseChunks.push(chunk));
      routerResponse.on('end', () => {
        response.writeHead(routerResponse.statusCode ?? 502, {
          'Access-Control-Allow-Origin': origin,
          'Cache-Control': 'no-store',
          'Content-Type':
            routerResponse.headers['content-type'] ??
            'application/json; charset=utf-8',
          Vary: 'Origin',
        });
        response.end(Buffer.concat(responseChunks));
      });
    },
  );

  upstream.on('timeout', () => {
    upstream.destroy(new Error('Timed out connecting to the router.'));
  });
  upstream.on('error', (error) => {
    if (!response.headersSent) {
      sendJson(response, 502, { error: error.message });
    }
  });
  upstream.end(body);
}

const server = http.createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/health') {
    sendJson(response, 200, {
      status: 'ok',
      routes: [
        'nonce',
        'salt',
        'response',
        'login',
        'check-expire',
        'guest-config',
        'wifi-config',
        'wifi-on',
      ],
      responseFields: ['response', 'enckey', 'enciv'],
    });
    return;
  }

  const origin = request.headers.origin;
  if (!origin || !allowedOrigins.has(origin)) {
    sendJson(response, 403, { error: 'Unapproved app origin.' });
    return;
  }

  response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Vary', 'Origin');
  response.setHeader('Cache-Control', 'no-store');

  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    response.end();
    return;
  }

  if (
    request.method !== 'POST' ||
    ![
      '/nonce',
      '/salt',
      '/response',
      '/login',
      '/check-expire',
      '/guest-config',
      '/wifi-config',
      '/wifi-on',
    ].includes(request.url)
  ) {
    sendJson(response, 404, { error: 'Not found.' });
    return;
  }

  const chunks = [];
  let bodyBytes = 0;
  let bodyTooLarge = false;
  request.on('data', (chunk) => {
    bodyBytes += chunk.length;
    if (bodyBytes > maxBodyBytes) {
      bodyTooLarge = true;
      return;
    }
    chunks.push(chunk);
  });

  request.on('end', () => {
    if (bodyTooLarge) {
      sendJson(response, 413, { error: 'Request body is too large.' });
      return;
    }

    const body = Buffer.concat(chunks).toString('utf8');
    if (request.url === '/guest-config') {
      let values;
      try {
        values = JSON.parse(body);
      } catch {
        sendJson(response, 400, { error: 'Invalid guest Wi-Fi status payload.' });
        return;
      }

      if (
        !values ||
        typeof values.sid !== 'string' ||
        !/^[A-Za-z0-9._~-]{1,256}$/.test(values.sid)
      ) {
        sendJson(response, 400, { error: 'A valid session ID is required.' });
        return;
      }

      forwardRequest(
        guestWifiStatusRequest,
        '',
        origin,
        response,
        cookieHeaderWithSessionId(guestWifiStatusRequest, values.sid),
      );
      return;
    }

    if (request.url === '/wifi-on' || request.url === '/wifi-config') {
      let values;
      try {
        values = JSON.parse(body);
      } catch {
        sendJson(response, 400, { error: 'Invalid guest Wi-Fi request payload.' });
        return;
      }

      if (
        !values ||
        typeof values.sid !== 'string' ||
        !/^[A-Za-z0-9._~-]{1,256}$/.test(values.sid) ||
        (request.url === '/wifi-config' && typeof values.enabled !== 'boolean')
      ) {
        sendJson(response, 400, {
          error: 'A valid session ID and enabled state are required.',
        });
        return;
      }

      const wifiFormFields = wifiOnRequest.body.urlencoded.map((field) => [
        field.key,
        field.value,
      ]);
      const requiredFields = ['encrypted', 'ct', 'ck'];
      const actualFields = wifiFormFields.map(([key]) => key.toLowerCase());
      if (
        wifiOnRequest.method !== 'POST' ||
        requiredFields.some((field) => !actualFields.includes(field)) ||
        values.encrypted !== '1' ||
        typeof values.ct !== 'string' ||
        !/^[A-Za-z0-9_-]+$/.test(values.ct) ||
        typeof values.ck !== 'string' ||
        !/^[A-Za-z0-9._-]+$/.test(values.ck)
      ) {
        sendJson(response, 500, {
          error: 'Guest Wi-Fi request must include valid encrypted, ct, and ck values.',
        });
        return;
      }

      const wifiFormBody = new URLSearchParams(
        wifiOnRequest.body.urlencoded.map((field) => [
          field.key,
          values[field.key.toLowerCase()],
        ]),
      ).toString();
      forwardRequest(
        wifiOnRequest,
        wifiFormBody,
        origin,
        response,
        cookieHeaderWithSessionId(wifiOnRequest, values.sid),
      );
      return;
    }

    if (request.url === '/check-expire') {
      let values;
      try {
        values = JSON.parse(body);
      } catch {
        sendJson(response, 400, { error: 'Invalid session-check payload.' });
        return;
      }

      if (
        !values ||
        typeof values.sid !== 'string' ||
        !/^[A-Za-z0-9._~-]{1,256}$/.test(values.sid)
      ) {
        sendJson(response, 400, { error: 'A valid session ID is required.' });
        return;
      }

      forwardRequest(
        checkExpireRequest,
        '',
        origin,
        response,
        cookieHeaderWithSessionId(checkExpireRequest, values.sid),
      );
      return;
    }

    if (request.url === '/login') {
      let values;
      try {
        values = JSON.parse(body);
      } catch {
        sendJson(response, 400, { error: 'Invalid login payload.' });
        return;
      }

      const expectedFields = loginRequest.body.urlencoded.map((field) =>
        field.key.toLowerCase(),
      );
      const actualFields =
        values && typeof values === 'object' && !Array.isArray(values)
          ? Object.keys(values).map((key) => key.toLowerCase())
          : [];
      const normalizedValues = new Map(
        values && typeof values === 'object' && !Array.isArray(values)
          ? Object.entries(values).map(([key, value]) => [
              key.toLowerCase(),
              value,
            ])
          : [],
      );
      const hasAllStringValues = expectedFields.every((key) => {
        const value = normalizedValues.get(key);
        return typeof value === 'string' && value.length > 0;
      });
      if (
        expectedFields.length !== 6 ||
        actualFields.length !== expectedFields.length ||
        expectedFields.some((key) => !actualFields.includes(key)) ||
        !hasAllStringValues
      ) {
        sendJson(response, 400, {
          error: 'Login payload must include all six generated form fields.',
        });
        return;
      }

      const loginFormFields = loginRequest.body.urlencoded.map((field) => {
        const value = normalizedValues.get(field.key.toLowerCase());
        if (typeof value !== 'string') {
          sendJson(response, 400, {
            error: `Missing login field ${field.key}.`,
          });
          return null;
        }
        return [field.key, value];
      });
      if (loginFormFields.some((field) => field === null)) {
        return;
      }
      const loginFormBody = new URLSearchParams(loginFormFields).toString();
      forwardRequest(loginRequest, loginFormBody, origin, response);
      return;
    }

    if (request.url === '/response') {
      let challenge;
      try {
        challenge = JSON.parse(body);
      } catch {
        sendJson(response, 400, { error: 'Invalid response-calculation body.' });
        return;
      }

      if (
        typeof challenge.salt !== 'string' ||
        typeof challenge.nonce !== 'string' ||
        !challenge.nonce ||
        !Number.isInteger(challenge.iterations) ||
        challenge.iterations < 0 ||
        challenge.iterations > 10000
      ) {
        sendJson(response, 400, { error: 'Invalid login challenge values.' });
        return;
      }

      try {
        sendJson(response, 200, {
          response: calculateResponse(
            challenge.salt,
            challenge.nonce,
            challenge.iterations,
          ),
          enckey: toRouterBase64Url(crypto.randomBytes(16).toString('base64')),
          enciv: toRouterBase64Url(crypto.randomBytes(16).toString('base64')),
        });
      } catch (error) {
        sendJson(response, 400, {
          error:
            error instanceof Error
              ? error.message
              : 'Could not calculate login response.',
        });
      }
      return;
    }

    if (request.url === '/nonce') {
      if (body !== expectedBody) {
        sendJson(response, 400, { error: 'Unexpected nonce request body.' });
        return;
      }
      forwardRequest(nonceRequest, body, origin, response);
      return;
    }

    const params = new URLSearchParams(body);
    const saltBodyFields = Array.from(params.keys()).sort();
    if (
      saltBodyFields.length !== 2 ||
      saltBodyFields[0] !== 'nonce' ||
      saltBodyFields[1] !== 'userhash' ||
      !params.get('nonce') ||
      !params.get('userhash')
    ) {
      sendJson(response, 400, { error: 'Unexpected salt request body.' });
      return;
    }

    forwardRequest(saltRequest, body, origin, response);
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Router nonce proxy listening at http://127.0.0.1:${port}`);
});

server.on('error', (error) => {
  console.error('Could not start router nonce proxy:', error);
  process.exitCode = 1;
});
