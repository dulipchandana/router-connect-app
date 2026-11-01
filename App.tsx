import { StatusBar } from 'expo-status-bar';
import * as Crypto from 'expo-crypto';
import { useEffect, useRef, useState } from 'react';
import {
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import wifiLoginCollection from './wifi-login.json';
import wifiSaltCollection from './wifi-log-salt.json';
import postmanHashCollection from './postman-hash.json';
import checkExpireCollection from './chek-cgi.json';

const nonceRequest = wifiLoginCollection.item[0]?.request;
const saltRequest = wifiSaltCollection.item[0]?.request;
const loginRequest = postmanHashCollection.item.find(
  (item) => item.name === 'login_web_app.cgi',
)?.request;
const checkExpireRequest = checkExpireCollection.item[0]?.request;
const usernameField = nonceRequest?.body.urlencoded.find(
  (field) => field.key === 'userName',
);
const loginCacheStorageKey = 'router-connect-app.login-cache';

interface LoginResponseCache {
  nonce: unknown;
  salt: unknown;
  response: unknown;
  login: unknown;
  sid: string;
  token: string | null;
  publicKey: string | null;
  userHash: string;
  nonceValue: string;
  randomKeyHash: string;
  loginResponse: string;
  loginResponseText: string;
  encryptionKey: string;
  encryptionIv: string;
}

function isLoginResponseCache(value: unknown): value is LoginResponseCache {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const cache = value as Record<string, unknown>;
  return (
    typeof cache.sid === 'string' &&
    cache.sid.length > 0 &&
    (cache.token === null || typeof cache.token === 'string') &&
    (cache.publicKey === null || typeof cache.publicKey === 'string') &&
    typeof cache.userHash === 'string' &&
    cache.userHash.length > 0 &&
    typeof cache.nonceValue === 'string' &&
    cache.nonceValue.length > 0 &&
    typeof cache.randomKeyHash === 'string' &&
    cache.randomKeyHash.length > 0 &&
    typeof cache.loginResponse === 'string' &&
    cache.loginResponse.length > 0 &&
    typeof cache.loginResponseText === 'string' &&
    typeof cache.encryptionKey === 'string' &&
    cache.encryptionKey.length > 0 &&
    typeof cache.encryptionIv === 'string' &&
    cache.encryptionIv.length > 0 &&
    'nonce' in cache &&
    'salt' in cache &&
    'response' in cache &&
    'login' in cache
  );
}

function loadLoginResponseCache(): LoginResponseCache | null {
  if (Platform.OS !== 'web' || typeof localStorage === 'undefined') {
    return null;
  }

  const storedCache = localStorage.getItem(loginCacheStorageKey);
  if (storedCache === null) {
    return null;
  }

  let parsedCache: unknown;
  try {
    parsedCache = JSON.parse(storedCache);
  } catch {
    localStorage.removeItem(loginCacheStorageKey);
    return null;
  }

  if (!isLoginResponseCache(parsedCache)) {
    localStorage.removeItem(loginCacheStorageKey);
    return null;
  }

  return parsedCache;
}

function findValueByKey(value: unknown, targetKey: string): unknown {
  if (Array.isArray(value)) {
    for (const item of value) {
      const match = findValueByKey(item, targetKey);
      if (match !== undefined) {
        return match;
      }
    }

    return undefined;
  }

  if (value === null || typeof value !== 'object') {
    return undefined;
  }

  for (const [key, item] of Object.entries(value)) {
    if (key.toLowerCase() === targetKey.toLowerCase()) {
      return item;
    }
  }

  for (const item of Object.values(value)) {
    const match = findValueByKey(item, targetKey);
    if (match !== undefined) {
      return match;
    }
  }

  return undefined;
}

function toRouterBase64Url(value: string): string {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '.');
}

export default function App() {
  const [sessionCache, setSessionCache] =
    useState<LoginResponseCache | null>(loadLoginResponseCache);
  const [sessionCheckResponse, setSessionCheckResponse] =
    useState<unknown | null>(null);
  const [isOn, setIsOn] = useState(false);
  const [switchedOnAt, setSwitchedOnAt] = useState<number | null>(null);
  const [duration, setDuration] = useState(0);
  const [userHash, setUserHash] = useState<string | null>(
    sessionCache?.userHash ?? null,
  );
  const [nonceValue, setNonceValue] = useState<string | null>(
    sessionCache?.nonceValue ?? null,
  );
  const [publicKey, setPublicKey] = useState<string | null>(
    sessionCache?.publicKey ?? null,
  );
  const [randomKeyHash, setRandomKeyHash] = useState<string | null>(
    sessionCache?.randomKeyHash ?? null,
  );
  const [loginResponse, setLoginResponse] = useState<string | null>(
    sessionCache?.loginResponse ?? null,
  );
  const [loginServerResponse, setLoginServerResponse] = useState<string | null>(
    sessionCache?.loginResponseText ?? null,
  );
  const [encryptionKey, setEncryptionKey] = useState<string | null>(
    sessionCache?.encryptionKey ?? null,
  );
  const [encryptionIv, setEncryptionIv] = useState<string | null>(
    sessionCache?.encryptionIv ?? null,
  );
  const [isRequestingNonce, setIsRequestingNonce] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const requestInProgressRef = useRef(false);
  const sessionCheckInProgressRef = useRef(false);
  const startupLoginStartedRef = useRef(false);

  const handleButtonPress = async (forceOn = false) => {
    if (requestInProgressRef.current) {
      return;
    }

    const nextIsOn = forceOn || !isOn;
    setIsOn(nextIsOn);
    if (!forceOn) {
      setSwitchedOnAt(nextIsOn ? Date.now() : null);
    }
    setDuration(0);
    if (!nextIsOn) {
      setRequestError(null);
      return;
    }
    if (!forceOn && sessionCache) {
      setRequestError(null);
      return;
    }

    requestInProgressRef.current = true;
    if (forceOn) {
      setSessionCache(null);
    }
    setUserHash(null);
    setNonceValue(null);
    setPublicKey(null);
    setRandomKeyHash(null);
    setLoginResponse(null);
    setLoginServerResponse(null);
    setEncryptionKey(null);
    setEncryptionIv(null);
    setSessionCheckResponse(null);
    setRequestError(null);
    setIsRequestingNonce(true);

    try {
      if (!nonceRequest?.url.raw || !usernameField?.value) {
        throw new Error('Nonce request URL or username is missing.');
      }

      const headers =
        Platform.OS === 'web'
          ? {
              Accept: 'application/json, text/plain, */*',
              'Content-Type': 'application/x-www-form-urlencoded',
            }
          : (nonceRequest.header ?? []).reduce<Record<string, string>>(
              (requestHeaders, header) => {
                if (
                  !['connection', 'cookie'].includes(header.key.toLowerCase())
                ) {
                  requestHeaders[header.key] = header.value;
                }
                return requestHeaders;
              },
              {},
            );
      headers['Content-Type'] = 'application/x-www-form-urlencoded';

      const requestUrl =
        Platform.OS === 'web'
          ? 'http://127.0.0.1:3001/nonce'
          : nonceRequest.url.raw;
      const response = await fetch(requestUrl, {
        method: nonceRequest.method,
        headers,
        body: `${encodeURIComponent(usernameField.key)}=${encodeURIComponent(
          usernameField.value,
        )}`,
      });

      if (!response.ok) {
        throw new Error(`Nonce request failed (HTTP ${response.status}).`);
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error('Router returned an invalid JSON response.');
      }

      const nonceValueFromPayload = findValueByKey(payload, 'nonce');
      if (typeof nonceValueFromPayload !== 'string' || !nonceValueFromPayload) {
        throw new Error('Nonce was not present in the router response.');
      }
      const nonce = nonceValueFromPayload;
      const publicKeyValue = findValueByKey(payload, 'pubkey');
      if (typeof publicKeyValue === 'string' && publicKeyValue) {
        setPublicKey(publicKeyValue);
      }
      const randomKeyValue = findValueByKey(payload, 'randomKey');
      if (typeof randomKeyValue !== 'string' || !randomKeyValue) {
        throw new Error('Random key was not present in the router response.');
      }
      const randomKey = randomKeyValue;
      setNonceValue(nonce);

      const userDigest = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        `${usernameField.value}:${nonce}`,
        { encoding: Crypto.CryptoEncoding.BASE64 },
      );
      setUserHash(toRouterBase64Url(userDigest));

      const randomKeyDigest = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        `${randomKey}:${nonce}`,
        { encoding: Crypto.CryptoEncoding.BASE64 },
      );
      setRandomKeyHash(toRouterBase64Url(randomKeyDigest));

      if (!saltRequest?.url.raw) {
        throw new Error('Salt request URL is missing.');
      }

      const saltBodyFields = saltRequest.body.urlencoded;
      const saltBodyValues: Record<string, string> = {
        userhash: toRouterBase64Url(userDigest),
        nonce: toRouterBase64Url(nonce),
      };
      const saltBody = new URLSearchParams(
        saltBodyFields.map((field) => {
          const value = saltBodyValues[field.key.toLowerCase()];
          if (value === undefined) {
            throw new Error(
              `Unsupported salt request field "${field.key}" in wifi-log-salt.json.`,
            );
          }
          return [field.key, value];
        }),
      ).toString();
      if (
        !saltBodyFields.some((field) => field.key.toLowerCase() === 'userhash') ||
        !saltBodyFields.some((field) => field.key.toLowerCase() === 'nonce')
      ) {
        throw new Error(
          'Salt request must define userhash and nonce fields in wifi-log-salt.json.',
        );
      }
      const saltHeaders =
        Platform.OS === 'web'
          ? {
              Accept: 'application/json, text/plain, */*',
              'Content-Type': 'application/x-www-form-urlencoded',
            }
          : (saltRequest.header ?? []).reduce<Record<string, string>>(
              (requestHeaders, header) => {
                if (
                  !['connection', 'cookie'].includes(header.key.toLowerCase())
                ) {
                  requestHeaders[header.key] = header.value;
                }
                return requestHeaders;
              },
              {},
            );
      saltHeaders['Content-Type'] = 'application/x-www-form-urlencoded';

      const saltResponse = await fetch(
        Platform.OS === 'web'
          ? 'http://127.0.0.1:3001/salt'
          : saltRequest.url.raw,
        {
          method: saltRequest.method,
          headers: saltHeaders,
          body: saltBody,
        },
      );
      if (!saltResponse.ok) {
        const errorBody = await saltResponse.text();
        let errorDetail = errorBody;
        try {
          const errorPayload: unknown = JSON.parse(errorBody);
          const message = findValueByKey(errorPayload, 'error');
          if (typeof message === 'string') {
            errorDetail = message;
          }
        } catch {
          // Keep the raw response text for non-JSON errors.
        }

        throw new Error(
          `Salt request failed (HTTP ${saltResponse.status})${
            errorDetail ? `: ${errorDetail.slice(0, 200)}` : '.'
          }`,
        );
      }

      let saltPayload: unknown;
      try {
        saltPayload = await saltResponse.json();
      } catch {
        throw new Error('Router returned an invalid salt response.');
      }

      const salt = findValueByKey(saltPayload, 'alati');
      if (typeof salt !== 'string') {
        throw new Error('Salt was not present in the router response.');
      }
      const iterationsValue = findValueByKey(payload, 'iterations');
      const iterations = Number(iterationsValue);
      if (!Number.isInteger(iterations) || iterations < 0) {
        throw new Error('A valid iteration count was not present in the nonce response.');
      }
      if (Platform.OS !== 'web') {
        throw new Error(
          'The password-derived response is calculated by the local Chrome proxy.',
        );
      }

      const responseResult = await fetch('http://127.0.0.1:3001/response', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ salt, nonce, iterations }),
      });
      let responsePayload: unknown;
      try {
        responsePayload = await responseResult.json();
      } catch {
        throw new Error('The local proxy returned an invalid response.');
      }
      if (!responseResult.ok) {
        const proxyError = findValueByKey(responsePayload, 'error');
        throw new Error(
          typeof proxyError === 'string'
            ? proxyError
            : `Response calculation failed (HTTP ${responseResult.status}).`,
        );
      }
      const calculatedResponse = findValueByKey(responsePayload, 'response');
      if (typeof calculatedResponse !== 'string' || !calculatedResponse) {
        throw new Error('The local proxy did not return a login response.');
      }
      const generatedEncryptionKey = findValueByKey(responsePayload, 'enckey');
      const generatedEncryptionIv = findValueByKey(responsePayload, 'enciv');
      if (
        typeof generatedEncryptionKey !== 'string' ||
        !generatedEncryptionKey ||
        typeof generatedEncryptionIv !== 'string' ||
        !generatedEncryptionIv
      ) {
        throw new Error('The local proxy did not return the encryption key and IV.');
      }
      setLoginResponse(calculatedResponse);
      setEncryptionKey(generatedEncryptionKey);
      setEncryptionIv(generatedEncryptionIv);

      if (!loginRequest?.url.raw || !loginRequest.body?.urlencoded) {
        throw new Error(
          'Login POST configuration is missing from postman-hash.json.',
        );
      }

      const loginValues: Record<string, string> = {
        userhash: toRouterBase64Url(userDigest),
        randomkeyhash: toRouterBase64Url(randomKeyDigest),
        response: calculatedResponse,
        nonce: toRouterBase64Url(nonce),
        enckey: generatedEncryptionKey,
        enciv: generatedEncryptionIv,
      };
      const loginBody = loginRequest.body.urlencoded.map((field) => {
        const value = loginValues[field.key.toLowerCase()];
        if (value === undefined) {
          throw new Error(
            `Unsupported login field "${field.key}" in postman-hash.json.`,
          );
        }
        return [field.key, value];
      });
      if (loginBody.length !== Object.keys(loginValues).length) {
        throw new Error('Login POST fields do not match the generated values.');
      }

      const loginPayload = Object.fromEntries(loginBody);
      const loginPostResponse = await fetch(
        Platform.OS === 'web'
          ? 'http://127.0.0.1:3001/login'
          : loginRequest.url.raw,
        {
          method: loginRequest.method,
          headers:
            Platform.OS === 'web'
              ? { 'Content-Type': 'application/json' }
              : (loginRequest.header ?? []).reduce<Record<string, string>>(
                  (requestHeaders, header) => {
                    if (
                      !['connection', 'cookie'].includes(
                        header.key.toLowerCase(),
                      )
                    ) {
                      requestHeaders[header.key] = header.value;
                    }
                    return requestHeaders;
                  },
                  {},
                ),
          body:
            Platform.OS === 'web'
              ? JSON.stringify(loginPayload)
              : new URLSearchParams(loginBody).toString(),
        },
      );
      const loginResponseBody = await loginPostResponse.text();
      if (!loginPostResponse.ok) {
        throw new Error(
          `Login POST failed (HTTP ${loginPostResponse.status})${
            loginResponseBody ? `: ${loginResponseBody.slice(0, 200)}` : '.'
          }`,
        );
      }
      let loginResponseJson: unknown;
      try {
        loginResponseJson = JSON.parse(loginResponseBody);
      } catch {
        throw new Error('The login response was not valid JSON.');
      }

      const sidValue = findValueByKey(loginResponseJson, 'sid');
      if (typeof sidValue !== 'string' || !sidValue) {
        throw new Error('The login response did not contain a session ID.');
      }
      const tokenValue = findValueByKey(loginResponseJson, 'token');
      const token =
        typeof tokenValue === 'string' && tokenValue ? tokenValue : null;
      setLoginServerResponse(JSON.stringify(loginResponseJson, null, 2));
      setSessionCache({
        nonce: payload,
        salt: saltPayload,
        response: responsePayload,
        login: loginResponseJson,
        sid: sidValue,
        token,
        publicKey:
          typeof publicKeyValue === 'string' && publicKeyValue
            ? publicKeyValue
            : null,
        userHash: toRouterBase64Url(userDigest),
        nonceValue: nonce,
        randomKeyHash: toRouterBase64Url(randomKeyDigest),
        loginResponse: calculatedResponse,
        loginResponseText: JSON.stringify(loginResponseJson, null, 2),
        encryptionKey: generatedEncryptionKey,
        encryptionIv: generatedEncryptionIv,
      });
    } catch (error) {
      setRequestError(
        Platform.OS === 'web' && error instanceof TypeError
          ? 'Cannot reach the local router proxy. Start it with "npm run proxy" and keep it running.'
          : error instanceof Error
            ? error.message
            : 'Could not request the router nonce.',
      );
    } finally {
      requestInProgressRef.current = false;
      setIsRequestingNonce(false);
    }
  };
  const handleButtonPressRef = useRef(handleButtonPress);
  handleButtonPressRef.current = handleButtonPress;

  useEffect(() => {
    if (
      Platform.OS === 'web' &&
      sessionCache === null &&
      !startupLoginStartedRef.current
    ) {
      startupLoginStartedRef.current = true;
      void handleButtonPressRef.current(true);
    }
  }, [sessionCache]);

  useEffect(() => {
    if (Platform.OS !== 'web' || typeof localStorage === 'undefined') {
      return;
    }
    if (sessionCache === null) {
      localStorage.removeItem(loginCacheStorageKey);
      return;
    }
    localStorage.setItem(loginCacheStorageKey, JSON.stringify(sessionCache));
  }, [sessionCache]);

  useEffect(() => {
    const sid = sessionCache?.sid;
    if (!sid || Platform.OS !== 'web') {
      return;
    }

    let checkTimer: ReturnType<typeof setTimeout>;
    const scheduleCheck = (delayMs: number, checkSession: () => void) => {
      checkTimer = setTimeout(checkSession, delayMs);
    };

    const checkSession = async () => {
      if (
        requestInProgressRef.current ||
        sessionCheckInProgressRef.current
      ) {
        scheduleCheck(1000, () => void checkSession());
        return;
      }
      if (!checkExpireRequest?.url.raw) {
        setRequestError('Session-check request URL is missing.');
        return;
      }

      sessionCheckInProgressRef.current = true;
      let shouldLogInAgain = false;
      let nextCheckDelayMs: number | null = null;
      try {
        const response = await fetch('http://127.0.0.1:3001/check-expire', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sid }),
        });
        let payload: unknown;
        try {
          payload = await response.json();
        } catch {
          throw new Error('The router returned an invalid session-check JSON response.');
        }
        setSessionCheckResponse(payload);
        if (!response.ok) {
          const errorMessage = findValueByKey(payload, 'error');
          throw new Error(
            typeof errorMessage === 'string'
              ? errorMessage
              : `Session check failed (HTTP ${response.status}).`,
          );
        }

        const expired = findValueByKey(payload, 'expired');
        if (typeof expired !== 'string') {
          throw new Error('The session-check response is missing expired.');
        }

        if (expired !== 'no') {
          shouldLogInAgain = true;
        } else {
          const expire = findValueByKey(payload, 'expire');
          const expireSeconds = Number(expire);
          if (
            typeof expire !== 'string' ||
            !Number.isFinite(expireSeconds) ||
            expireSeconds <= 0
          ) {
            throw new Error(
              'The valid session response is missing a positive expire value.',
            );
          }

          setRequestError(null);
          nextCheckDelayMs = Math.max(1000, expireSeconds * 500);
        }
      } catch (error) {
        setRequestError(
          error instanceof Error
            ? error.message
            : 'Could not check the router session.',
        );
      } finally {
        sessionCheckInProgressRef.current = false;
      }

      if (shouldLogInAgain) {
        await handleButtonPressRef.current(true);
      } else if (nextCheckDelayMs !== null) {
        scheduleCheck(nextCheckDelayMs, () => void checkSession());
      }
    };

    scheduleCheck(0, () => void checkSession());
    return () => clearTimeout(checkTimer);
  }, [sessionCache?.sid]);

  useEffect(() => {
    if (!isOn || switchedOnAt === null) {
      return;
    }

    const updateDuration = () => setDuration(Date.now() - switchedOnAt);
    updateDuration();
    const interval = setInterval(updateDuration, 1000);

    return () => clearInterval(interval);
  }, [isOn, switchedOnAt]);

  const formattedDuration = [
    Math.floor(duration / 3_600_000),
    Math.floor((duration % 3_600_000) / 60_000),
    Math.floor((duration % 60_000) / 1000),
  ]
    .map((part) => String(part).padStart(2, '0'))
    .join(':');

  return (
    <ScrollView
      contentContainerStyle={styles.container}
      showsVerticalScrollIndicator
    >
      <StatusBar style="light" />
      <View style={styles.content}>
        <Text style={styles.title}>
          {isOn ? 'Disable' : 'Enable'} NOKIA-45AA_Guest wifi
        </Text>
        <Text style={styles.description}>
          This switch is a visual status only; it does not change your router
          settings.
        </Text>

        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`Turn ${isOn ? 'off' : 'on'}`}
          accessibilityState={{ checked: isOn }}
          disabled={isRequestingNonce}
          onPress={() => void handleButtonPress()}
          style={({ pressed }) => [
            styles.button,
            isOn && styles.buttonOn,
            pressed && styles.buttonPressed,
          ]}
        >
          <View style={[styles.buttonInner, isOn && styles.buttonInnerOn]}>
            <Text style={[styles.buttonLabel, isOn && styles.buttonLabelOn]}>
              {isOn ? 'ON' : 'OFF'}
            </Text>
          </View>
        </Pressable>

        <View style={styles.status}>
          <View style={[styles.statusDot, isOn && styles.statusDotOn]} />
          <Text style={styles.statusText}>
            {isOn ? 'IT’S ON' : 'IT’S OFF'}
          </Text>
        </View>

        <View style={styles.details}>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Switched on time</Text>
            <Text style={styles.detailValue}>
              {switchedOnAt === null
                ? '--'
                : new Date(switchedOnAt).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
            </Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Switched on duration</Text>
            <Text style={styles.detailValue}>
              {isOn ? formattedDuration : '--'}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>User hash</Text>
            <Text selectable style={styles.hashValue}>
              {isRequestingNonce ? 'Fetching nonce...' : (userHash ?? '--')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>Nonce</Text>
            <Text selectable style={styles.hashValue}>
              {isRequestingNonce ? 'Fetching nonce...' : (nonceValue ?? '--')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>Cached router public key</Text>
            <Text selectable style={styles.responseValue}>
              {isRequestingNonce
                ? 'Fetching nonce...'
                : (publicKey ?? 'Not returned by the nonce response.')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>RandomKeyhash</Text>
            <Text selectable style={styles.hashValue}>
              {isRequestingNonce
                ? 'Calculating hash...'
                : (randomKeyHash ?? '--')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>Response</Text>
            <Text selectable style={styles.hashValue}>
              {isRequestingNonce
                ? 'Calculating response...'
                : (loginResponse ?? '--')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>enckey</Text>
            <Text selectable style={styles.hashValue}>
              {isRequestingNonce
                ? 'Generating...'
                : (encryptionKey ?? '--')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>enciv</Text>
            <Text selectable style={styles.hashValue}>
              {isRequestingNonce
                ? 'Generating...'
                : (encryptionIv ?? '--')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>Login request response JSON</Text>
            <Text selectable style={styles.responseValue}>
              {isRequestingNonce
                ? 'Waiting for login response...'
                : (loginServerResponse ?? 'No response yet.')}
            </Text>
          </View>
          <View style={styles.hashRow}>
            <Text style={styles.detailLabel}>Session check response JSON</Text>
            <Text selectable style={styles.responseValue}>
              {sessionCheckResponse === null
                ? 'Waiting for session check...'
                : JSON.stringify(sessionCheckResponse, null, 2)}
            </Text>
          </View>
          {requestError !== null && (
            <Text accessibilityRole="alert" style={styles.errorText}>
              {requestError}
            </Text>
          )}
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: '#101522',
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 28,
    paddingVertical: 24,
  },
  content: {
    width: '100%',
    alignItems: 'center',
  },
  title: {
    color: '#F5F7FC',
    fontSize: 32,
    fontWeight: '700',
    lineHeight: 40,
    textAlign: 'center',
    letterSpacing: -1.2,
    marginBottom: 22,
  },
  description: {
    color: '#A7AEC0',
    fontSize: 16,
    lineHeight: 24,
    marginTop: 14,
    marginBottom: 30,
    textAlign: 'center',
  },
  button: {
    width: 224,
    height: 224,
    borderRadius: 112,
    borderWidth: 1,
    borderColor: '#394255',
    backgroundColor: '#171E2E',
    alignItems: 'center',
    justifyContent: 'center',
    elevation: 12,
    shadowColor: '#000000',
    shadowOffset: { width: 0, height: 12 },
    shadowOpacity: 0.35,
    shadowRadius: 18,
  },
  buttonOn: {
    borderColor: '#78F0C0',
    backgroundColor: '#17372F',
    shadowColor: '#41D9A1',
    shadowOpacity: 0.24,
  },
  buttonPressed: {
    transform: [{ scale: 0.96 }],
  },
  buttonInner: {
    width: 176,
    height: 176,
    borderRadius: 88,
    borderWidth: 1,
    borderColor: '#30394C',
    alignItems: 'center',
    justifyContent: 'center',
  },
  buttonInnerOn: {
    borderColor: '#3E9D7B',
  },
  buttonLabel: {
    color: '#E4E9F3',
    fontSize: 25,
    fontWeight: '700',
    letterSpacing: 5,
    marginLeft: 5,
  },
  buttonLabelOn: {
    color: '#78F0C0',
  },
  status: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 42,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#687184',
    marginRight: 10,
  },
  statusDotOn: {
    backgroundColor: '#78F0C0',
  },
  statusText: {
    color: '#A7AEC0',
    fontSize: 12,
    fontWeight: '700',
    letterSpacing: 2,
  },
  details: {
    width: '100%',
    marginTop: 30,
    paddingHorizontal: 18,
    paddingVertical: 8,
    borderRadius: 16,
    backgroundColor: '#171E2E',
  },
  detailRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
  },
  detailLabel: {
    color: '#A7AEC0',
    fontSize: 14,
  },
  detailValue: {
    color: '#F5F7FC',
    fontSize: 14,
    fontWeight: '600',
    fontVariant: ['tabular-nums'],
  },
  hashRow: {
    paddingVertical: 12,
    borderTopWidth: 1,
    borderTopColor: '#30394C',
  },
  hashValue: {
    color: '#F5F7FC',
    fontSize: 13,
    lineHeight: 19,
    marginTop: 8,
  },
  responseValue: {
    color: '#F5F7FC',
    fontFamily: 'monospace',
    fontSize: 12,
    lineHeight: 18,
    marginTop: 8,
    width: '100%',
  },
  errorText: {
    color: '#FF9B9B',
    fontSize: 13,
    lineHeight: 19,
    paddingVertical: 8,
  },
});
