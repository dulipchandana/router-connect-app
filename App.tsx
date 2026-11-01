import { StatusBar } from 'expo-status-bar';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import {
  createLoginCryptoValues,
  encryptGuestPayload,
} from './guestWifiCrypto';
import { useEffect, useRef, useState } from 'react';
import {
  Animated,
  Easing,
  Platform,
  Pressable,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import wifiLoginCollection from './wifi-login.json';
import wifiSaltCollection from './wifi-log-salt.json';
import postmanHashCollection from './postman-hash.json';
import checkExpireCollection from './chek-cgi.json';
import guestWifiStatusCollection from './postman-wifi-status.json';
import wifiOnCollection from './wifi-on.json';
import { getProxyErrorMessage, getProxyUrl } from './routerProxy';

const nonceRequest = wifiLoginCollection.item[0]?.request;
const saltRequest = wifiSaltCollection.item[0]?.request;
const loginRequest = postmanHashCollection.item.find(
  (item) => item.name === 'login_web_app.cgi',
)?.request;
const checkExpireRequest = checkExpireCollection.item[0]?.request;
const guestWifiStatusRequest = guestWifiStatusCollection.item[0]?.request;
const wifiOnRequest = wifiOnCollection.item[0]?.request;
const usernameField = nonceRequest?.body.urlencoded.find(
  (field) => field.key === 'userName',
);
const loginCacheStorageKey = 'router-connect-app.login-cache';
const routerPasswordStorageKey = 'router-connect-app.router-password';

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

function getGuestWifiEnabled(payload: unknown): boolean {
  const enabledValues: unknown[] = [];
  const visit = (value: unknown) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value === null || typeof value !== 'object') {
      return;
    }

    const record = value as Record<string, unknown>;
    const ssid = Object.entries(record).find(
      ([key]) => key.toLowerCase() === 'ssid',
    )?.[1];
    if (ssid === 'NOKIA-45AA_Guest') {
      const enable = Object.entries(record).find(
        ([key]) => key.toLowerCase() === 'enable',
      )?.[1];
      enabledValues.push(enable);
    }

    Object.values(record).forEach(visit);
  };
  visit(payload);

  if (enabledValues.length === 0) {
    throw new Error('Guest Wi-Fi status did not include SSID "NOKIA-45AA_Guest".');
  }

  return enabledValues.every((value) => value === 1 || value === '1');
}

function toRouterBase64Url(value: string): string {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '.');
}

function createRouterHeaders(
  configuredHeaders: { key: string; value: string }[] | undefined,
  sid?: string,
): Record<string, string> {
  const headers: Record<string, string> = {};
  let configuredCookie = '';

  for (const header of configuredHeaders ?? []) {
    const key = header.key.toLowerCase();
    if (key === 'connection') {
      continue;
    }
    if (key === 'cookie') {
      configuredCookie = header.value;
      continue;
    }
    headers[header.key] = header.value;
  }

  if (sid !== undefined) {
    let replacedSid = false;
    const cookies = configuredCookie
      .split(';')
      .map((cookie) => cookie.trim())
      .filter(Boolean)
      .map((cookie) => {
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
      cookies.push(`sid=${sid}`);
    }
    headers.Cookie = cookies.join('; ');
  }

  return headers;
}
export default function App() {
  const [sessionCache, setSessionCache] =
    useState<LoginResponseCache | null>(loadLoginResponseCache);
  const [routerPassword, setRouterPassword] = useState<string | null>(null);
  const [routerPasswordInput, setRouterPasswordInput] = useState('');
  const [isRouterPasswordLoaded, setIsRouterPasswordLoaded] = useState(
    Platform.OS === 'web',
  );
  const [isSendingGuestWifi, setIsSendingGuestWifi] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isOn, setIsOn] = useState(false);
  const [switchedOnAt, setSwitchedOnAt] = useState<number | null>(null);
  const [duration, setDuration] = useState(0);
  const pullStartY = useRef<number | null>(null);
  const scrollOffsetY = useRef(0);
  const [isRequestingNonce, setIsRequestingNonce] = useState(false);
  const isButtonBusy = isRequestingNonce || isSendingGuestWifi;
  const [buttonProgress] = useState(() => new Animated.Value(0));
  const [requestError, setRequestError] = useState<string | null>(null);
  const requestInProgressRef = useRef(false);
  const sessionCheckInProgressRef = useRef(false);
  const guestWifiRequestInProgressRef = useRef(false);
  const startupLoginStartedRef = useRef(false);

  useEffect(() => {
    if (Platform.OS !== 'web' || typeof document === 'undefined') {
      return;
    }

    const rootOverscrollBehavior = document.documentElement.style.overscrollBehaviorY;
    const bodyOverscrollBehavior = document.body.style.overscrollBehaviorY;
    document.documentElement.style.overscrollBehaviorY = 'contain';
    document.body.style.overscrollBehaviorY = 'contain';

    return () => {
      document.documentElement.style.overscrollBehaviorY =
        rootOverscrollBehavior;
      document.body.style.overscrollBehaviorY = bodyOverscrollBehavior;
    };
  }, []);

  useEffect(() => {
    if (Platform.OS === 'web') {
      return;
    }

    let active = true;
    void SecureStore.getItemAsync(routerPasswordStorageKey)
      .then((password) => {
        if (active) {
          setRouterPassword(password);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setRequestError(
            error instanceof Error
              ? `Could not read the saved router password: ${error.message}`
              : 'Could not read the saved router password.',
          );
        }
      })
      .finally(() => {
        if (active) {
          setIsRouterPasswordLoaded(true);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  const refreshGuestWifiStatus = async (
    activeSession: LoginResponseCache,
  ): Promise<boolean> => {
    if (!guestWifiStatusRequest?.url.raw) {
      throw new Error('Guest Wi-Fi status request URL is missing.');
    }

    const response =
      Platform.OS === 'web'
        ? await fetch(getProxyUrl('/guest-config'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sid: activeSession.sid }),
          })
        : await fetch(guestWifiStatusRequest.url.raw, {
            method: guestWifiStatusRequest.method,
            headers: createRouterHeaders(
              guestWifiStatusRequest.header,
              activeSession.sid,
            ),
            credentials: 'include',
          });
    const responseText = await response.text();
    let payload: unknown;
    try {
      payload = JSON.parse(responseText);
    } catch {
      throw new Error('The router returned invalid guest Wi-Fi status JSON.');
    }
    if (!response.ok) {
      const errorMessage = findValueByKey(payload, 'error');
      throw new Error(
        typeof errorMessage === 'string'
          ? errorMessage
          : `Guest Wi-Fi status request failed (HTTP ${response.status}).`,
      );
    }

    const isGuestWifiEnabled = getGuestWifiEnabled(payload);
    setIsOn(isGuestWifiEnabled);
    setSwitchedOnAt((previousStartTime) =>
      isGuestWifiEnabled ? (previousStartTime ?? Date.now()) : null,
    );
    if (!isGuestWifiEnabled) {
      setDuration(0);
    }
    return isGuestWifiEnabled;
  };

  const sendGuestWifiRequest = async (
    activeSession: LoginResponseCache,
    refreshExpiredSession = true,
    enableGuestWifi = true,
  ) => {
    if (guestWifiRequestInProgressRef.current) {
      return;
    }

    guestWifiRequestInProgressRef.current = true;
    setIsSendingGuestWifi(true);
    setRequestError(null);
    let ownsSessionCheck = false;
    let sessionExpired = false;
    try {
      if (sessionCheckInProgressRef.current) {
        throw new Error('A router session check is already in progress. Try again shortly.');
      }
      sessionCheckInProgressRef.current = true;
      ownsSessionCheck = true;

      if (!checkExpireRequest?.url.raw) {
        throw new Error('Session-check request URL is missing.');
      }
      const sessionResponse =
        Platform.OS === 'web'
          ? await fetch(getProxyUrl('/check-expire'), {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ sid: activeSession.sid }),
            })
          : await fetch(checkExpireRequest.url.raw, {
              method: checkExpireRequest.method,
              headers: createRouterHeaders(
                checkExpireRequest.header,
                activeSession.sid,
              ),
              credentials: 'include',
            });
      let sessionPayload: unknown;
      try {
        sessionPayload = await sessionResponse.json();
      } catch {
        throw new Error('The router returned an invalid session-check JSON response.');
      }
      if (!sessionResponse.ok) {
        const errorMessage = findValueByKey(sessionPayload, 'error');
        throw new Error(
          typeof errorMessage === 'string'
            ? errorMessage
            : `Session check failed (HTTP ${sessionResponse.status}).`,
        );
      }

      const expired = findValueByKey(sessionPayload, 'expired');
      if (expired !== 'no') {
        if (refreshExpiredSession) {
          sessionExpired = true;
        } else {
          throw new Error('The refreshed router session is still expired.');
        }
      }

      if (!sessionExpired) {
        const expire = findValueByKey(sessionPayload, 'expire');
        if (
          typeof expire !== 'string' ||
          !Number.isFinite(Number(expire)) ||
          Number(expire) <= 0
        ) {
          throw new Error('The valid session response is missing a positive expire value.');
        }

        if (!guestWifiStatusRequest?.url.raw) {
          throw new Error('Guest Wi-Fi status request URL is missing.');
        }
        const settingsResponse =
          Platform.OS === 'web'
            ? await fetch(getProxyUrl('/guest-config'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sid: activeSession.sid }),
              })
            : await fetch(guestWifiStatusRequest.url.raw, {
                method: guestWifiStatusRequest.method,
                headers: createRouterHeaders(
                  guestWifiStatusRequest.header,
                  activeSession.sid,
                ),
                credentials: 'include',
              });
        const settingsText = await settingsResponse.text();
        let settingsPayload: unknown;
        try {
          settingsPayload = JSON.parse(settingsText);
        } catch {
          throw new Error('The router returned invalid guest Wi-Fi settings JSON.');
        }
        if (!settingsResponse.ok) {
          const errorMessage = findValueByKey(settingsPayload, 'error');
          throw new Error(
            typeof errorMessage === 'string'
              ? errorMessage
              : `Guest Wi-Fi settings request failed (HTTP ${settingsResponse.status}).`,
          );
        }

        if (!activeSession.publicKey) {
          throw new Error('The cached router public key is missing; sign in again.');
        }
        if (!activeSession.token) {
          throw new Error('The cached router CSRF token is missing; sign in again.');
        }

        const wlanList = findValueByKey(settingsPayload, 'wlan_list');
        const guestList = findValueByKey(settingsPayload, 'guest_list');
        if (!Array.isArray(wlanList) || !Array.isArray(guestList)) {
          throw new Error('Guest Wi-Fi settings are missing wlan_list or guest_list.');
        }

        const targetGuestSsid = 'NOKIA-45AA_Guest';
        const primaryGuest = guestList[0];
        if (
          primaryGuest === null ||
          typeof primaryGuest !== 'object' ||
          Array.isArray(primaryGuest) ||
          !Number.isInteger(primaryGuest.MappedWlanIdx) ||
          primaryGuest.MappedWlanIdx < 1
        ) {
          throw new Error('Guest Wi-Fi settings do not include a valid mapped WLAN index.');
        }

        const mappedWlan = wlanList[primaryGuest.MappedWlanIdx - 1];
        if (
          mappedWlan === null ||
          typeof mappedWlan !== 'object' ||
          Array.isArray(mappedWlan) ||
          mappedWlan.SSID !== targetGuestSsid ||
          typeof mappedWlan.PreSharedKey !== 'string'
        ) {
          throw new Error(
            `The mapped WLAN is missing the "${targetGuestSsid}" SSID or its password.`,
          );
        }

        const plaintextPayload = [
          'act=ConfigWhwGuest',
          'iso=',
          'dura=',
          'accessType=password',
          `enable=${enableGuestWifi ? 1 : 0}`,
          `wl_ssid=${encodeURIComponent(mappedWlan.SSID.trim())}`,
          `wpaKey=${encodeURIComponent(mappedWlan.PreSharedKey.trim())}`,
          'dual_band=0',
          'ssid_num=',
          'sync_value=false',
          'wpa3_support=1',
          `csrf_token=${activeSession.token}`,
        ].join('&');
        const encryptedRequest = await encryptGuestPayload(
          activeSession.publicKey,
          plaintextPayload,
        );
        if (!wifiOnRequest?.url.raw || !wifiOnRequest.body?.urlencoded) {
          throw new Error('Guest Wi-Fi configuration request is missing its URL or fields.');
        }
        const encryptedValues: Record<string, string> = {
          encrypted: encryptedRequest.encrypted,
          ct: encryptedRequest.ct,
          ck: encryptedRequest.ck,
        };
        const wifiFormBody = new URLSearchParams(
          wifiOnRequest.body.urlencoded.map((field) => {
            const value = encryptedValues[field.key.toLowerCase()];
            if (value === undefined) {
              throw new Error(
                `Unsupported Wi-Fi configuration field "${field.key}".`,
              );
            }
            return [field.key, value];
          }),
        ).toString();
        const wifiResponse =
          Platform.OS === 'web'
            ? await fetch(getProxyUrl('/wifi-config'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  sid: activeSession.sid,
                  enabled: enableGuestWifi,
                  ...encryptedRequest,
                }),
              })
            : await fetch(wifiOnRequest.url.raw, {
                method: wifiOnRequest.method,
                headers: {
                  ...createRouterHeaders(
                    wifiOnRequest.header,
                    activeSession.sid,
                  ),
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: wifiFormBody,
                credentials: 'include',
              });
        const responseText = await wifiResponse.text();
        let wifiPayload: unknown = responseText;
        try {
          wifiPayload = JSON.parse(responseText);
        } catch {
          // Keep the raw response when the router does not return JSON.
        }
        if (!wifiResponse.ok) {
          const errorMessage = findValueByKey(wifiPayload, 'error');
          throw new Error(
            typeof errorMessage === 'string'
              ? errorMessage
              : `Guest Wi-Fi update failed (HTTP ${wifiResponse.status}).`,
          );
        }

        const routerResult = findValueByKey(wifiPayload, 'result');
        const routerReason = findValueByKey(wifiPayload, 'reason');
        if (
          !(routerResult === 0 || routerResult === '0') ||
          !(routerReason === 0 || routerReason === '0')
        ) {
          throw new Error('The router did not confirm the guest Wi-Fi configuration update.');
        }

        await refreshGuestWifiStatus(activeSession);
      }
    } catch (error) {
      setRequestError(
        error instanceof Error
          ? error.message
          : 'Could not send the guest Wi-Fi request.',
      );
    } finally {
      if (ownsSessionCheck) {
        sessionCheckInProgressRef.current = false;
      }
      guestWifiRequestInProgressRef.current = false;
      setIsSendingGuestWifi(false);
    }

    if (sessionExpired) {
      const refreshedSession = await handleButtonPressRef.current(true);
      if (refreshedSession) {
        await sendGuestWifiRequest(
          refreshedSession,
          false,
          enableGuestWifi,
        );
      }
    }
  };

  const handleButtonPress = async (
    forceOn = false,
  ): Promise<LoginResponseCache | null> => {
    if (requestInProgressRef.current) {
      return null;
    }
    if (Platform.OS !== 'web' && !routerPassword) {
      setRequestError('Save the router password on this device before connecting.');
      return null;
    }

    const nextIsOn = forceOn || !isOn;
    setDuration(0);
    if (!forceOn && sessionCache) {
      setRequestError(null);
      await sendGuestWifiRequest(sessionCache, true, nextIsOn);
      return null;
    }
    if (!nextIsOn) {
      setIsOn(false);
      setSwitchedOnAt(null);
      setRequestError(null);
      return null;
    }

    requestInProgressRef.current = true;
    if (forceOn) {
      setSessionCache(null);
    }
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
          ? getProxyUrl('/nonce')
          : nonceRequest.url.raw;
      const response = await fetch(requestUrl, {
        method: nonceRequest.method,
        headers,
        body: `${encodeURIComponent(usernameField.key)}=${encodeURIComponent(
          usernameField.value,
        )}`,
        ...(Platform.OS === 'web' ? {} : { credentials: 'include' as const }),
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
      const randomKeyValue = findValueByKey(payload, 'randomKey');
      if (typeof randomKeyValue !== 'string' || !randomKeyValue) {
        throw new Error('Random key was not present in the router response.');
      }
      const randomKey = randomKeyValue;

      const userDigest = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        `${usernameField.value}:${nonce}`,
        { encoding: Crypto.CryptoEncoding.BASE64 },
      );
      const randomKeyDigest = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        `${randomKey}:${nonce}`,
        { encoding: Crypto.CryptoEncoding.BASE64 },
      );
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
          ? getProxyUrl('/salt')
          : saltRequest.url.raw,
        {
          method: saltRequest.method,
          headers: saltHeaders,
          body: saltBody,
          ...(Platform.OS === 'web' ? {} : { credentials: 'include' as const }),
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
      let responsePayload: unknown;
      let calculatedResponse: unknown;
      let generatedEncryptionKey: unknown;
      let generatedEncryptionIv: unknown;
      if (Platform.OS === 'web') {
        const responseResult = await fetch(getProxyUrl('/response'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ salt, nonce, iterations }),
        });
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
        calculatedResponse = findValueByKey(responsePayload, 'response');
        generatedEncryptionKey = findValueByKey(responsePayload, 'enckey');
        generatedEncryptionIv = findValueByKey(responsePayload, 'enciv');
      } else {
        if (!routerPassword) {
          throw new Error('Save the router password on this device before connecting.');
        }
        const cryptoValues = await createLoginCryptoValues(
          usernameField.value,
          routerPassword,
          salt,
          nonce,
          iterations,
        );
        responsePayload = cryptoValues;
        calculatedResponse = cryptoValues.response;
        generatedEncryptionKey = cryptoValues.enckey;
        generatedEncryptionIv = cryptoValues.enciv;
      }
      if (typeof calculatedResponse !== 'string' || !calculatedResponse) {
        throw new Error('Could not calculate the router login response.');
      }
      if (
        typeof generatedEncryptionKey !== 'string' ||
        !generatedEncryptionKey ||
        typeof generatedEncryptionIv !== 'string' ||
        !generatedEncryptionIv
      ) {
        throw new Error('Could not generate the router login encryption key and IV.');
      }
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
          ? getProxyUrl('/login')
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
          ...(Platform.OS === 'web' ? {} : { credentials: 'include' as const }),
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
      const loginResponseText = JSON.stringify(loginResponseJson, null, 2);
      const newSessionCache: LoginResponseCache = {
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
        loginResponseText,
        encryptionKey: generatedEncryptionKey,
        encryptionIv: generatedEncryptionIv,
      };
      setSessionCache(newSessionCache);
      if (forceOn) {
        await refreshGuestWifiStatus(newSessionCache);
      } else {
        await sendGuestWifiRequest(newSessionCache);
      }
      return newSessionCache;
    } catch (error) {
      setRequestError(
        Platform.OS === 'web' && error instanceof TypeError
          ? getProxyErrorMessage()
          : error instanceof Error
            ? error.message
            : 'Could not request the router nonce.',
      );
      return null;
    } finally {
      requestInProgressRef.current = false;
      setIsRequestingNonce(false);
    }
  };
  const handleButtonPressRef = useRef(handleButtonPress);
  useEffect(() => {
    handleButtonPressRef.current = handleButtonPress;
  });

  const saveRouterPassword = async () => {
    const password = routerPasswordInput;
    if (!password.trim()) {
      setRequestError('Enter the router password to continue.');
      return;
    }

    try {
      await SecureStore.setItemAsync(routerPasswordStorageKey, password);
      setRouterPassword(password);
      setRouterPasswordInput('');
      setRequestError(null);
    } catch (error) {
      setRequestError(
        error instanceof Error
          ? `Could not securely save the router password: ${error.message}`
          : 'Could not securely save the router password.',
      );
    }
  };

  const handleRefresh = async () => {
    if (requestInProgressRef.current || guestWifiRequestInProgressRef.current) {
      setRequestError('Please wait for the current router request to finish.');
      return;
    }
    if (!sessionCache) {
      setRequestError('The router session is not ready yet. Try again shortly.');
      return;
    }

    setIsRefreshing(true);
    setRequestError(null);
    try {
      await refreshGuestWifiStatus(sessionCache);
    } catch (error) {
      setRequestError(
        error instanceof Error
          ? error.message
          : 'Could not refresh guest Wi-Fi status.',
      );
    } finally {
      setIsRefreshing(false);
    }
  };

  const changeRouterPassword = async () => {
    try {
      await SecureStore.deleteItemAsync(routerPasswordStorageKey);
      setRouterPassword(null);
      setSessionCache(null);
      setIsOn(false);
      setSwitchedOnAt(null);
      startupLoginStartedRef.current = false;
      setRequestError(null);
    } catch (error) {
      setRequestError(
        error instanceof Error
          ? `Could not remove the saved router password: ${error.message}`
          : 'Could not remove the saved router password.',
      );
    }
  };

  const validateCachedSession = async (cachedSession: LoginResponseCache | null) => {
    if (!cachedSession?.sid || !checkExpireRequest?.url.raw) {
      return false;
    }

    try {
      const response =
        Platform.OS === 'web'
          ? await fetch(getProxyUrl('/check-expire'), {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ sid: cachedSession.sid }),
            })
          : await fetch(checkExpireRequest.url.raw, {
              method: checkExpireRequest.method,
              headers: createRouterHeaders(
                checkExpireRequest.header,
                cachedSession.sid,
              ),
              credentials: 'include',
            });

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error('The router returned an invalid session-check JSON response.');
      }

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

      if (expired === 'no') {
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
        return true;
      }

      return false;
    } catch (error) {
      setRequestError(
        error instanceof Error
          ? error.message
          : 'Could not check the router session.',
      );
      return false;
    }
  };

  useEffect(() => {
    if (startupLoginStartedRef.current) {
      return;
    }

    if (Platform.OS !== 'web') {
      if (!isRouterPasswordLoaded || !routerPassword) {
        return;
      }
      startupLoginStartedRef.current = true;
      void handleButtonPressRef.current(true);
      return;
    }

    startupLoginStartedRef.current = true;

    if (sessionCache?.sid) {
      void (async () => {
        const isSessionValid = await validateCachedSession(sessionCache);
        if (isSessionValid) {
          try {
            await refreshGuestWifiStatus(sessionCache);
          } catch (error) {
            setIsOn(false);
            setRequestError(
              error instanceof Error
                ? error.message
                : 'Could not load guest Wi-Fi status.',
            );
          }
        } else {
          await handleButtonPressRef.current(true);
        }
      })();
      return;
    }

    void handleButtonPressRef.current(true);
  }, [isRouterPasswordLoaded, routerPassword, sessionCache]);

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
    if (!sid || !checkExpireRequest?.url.raw) {
      return;
    }

    let checkTimer: ReturnType<typeof setTimeout>;
    const scheduleCheck = (delayMs: number, checkSession: () => void) => {
      checkTimer = setTimeout(checkSession, delayMs);
    };

    const checkSession = async () => {
      if (
        requestInProgressRef.current ||
        sessionCheckInProgressRef.current ||
        guestWifiRequestInProgressRef.current
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
        const response =
          Platform.OS === 'web'
            ? await fetch(getProxyUrl('/check-expire'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sid }),
              })
            : await fetch(checkExpireRequest.url.raw, {
                method: checkExpireRequest.method,
                headers: createRouterHeaders(
                  checkExpireRequest.header,
                  sid,
                ),
                credentials: 'include',
              });
        let payload: unknown;
        try {
          payload = await response.json();
        } catch {
          throw new Error('The router returned an invalid session-check JSON response.');
        }
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
    if (!isButtonBusy) {
      buttonProgress.setValue(0);
      return;
    }

    const animation = Animated.loop(
      Animated.timing(buttonProgress, {
        toValue: 1,
        duration: 900,
        easing: Easing.linear,
        useNativeDriver: false,
      }),
    );
    animation.start();

    return () => animation.stop();
  }, [isButtonBusy, buttonProgress]);

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
  const buttonProgressRotation = buttonProgress.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });

  return (
    <ScrollView
      contentContainerStyle={styles.container}
      refreshControl={
        Platform.OS === 'android' ? (
          <RefreshControl
            colors={['#78F0C0']}
            onRefresh={() => void handleRefresh()}
            progressBackgroundColor="#171E2E"
            refreshing={isRefreshing}
          />
        ) : undefined
      }
      showsVerticalScrollIndicator={false}
      onScroll={(event) => {
        scrollOffsetY.current = event.nativeEvent.contentOffset.y;
      }}
      onTouchStart={(event) => {
        if (Platform.OS === 'web' && scrollOffsetY.current <= 0) {
          pullStartY.current = event.nativeEvent.pageY;
        }
      }}
      onTouchEnd={(event) => {
        const startY = pullStartY.current;
        pullStartY.current = null;
        if (
          Platform.OS === 'web' &&
          startY !== null &&
          scrollOffsetY.current <= 0 &&
          event.nativeEvent.pageY - startY >= 64
        ) {
          void handleRefresh();
        }
      }}
      onTouchCancel={() => {
        pullStartY.current = null;
      }}
    >
      <StatusBar style="light" />
      <View style={styles.content}>
        {Platform.OS === 'web' && isRefreshing && (
          <Text style={styles.credentialMessage}>Refreshing Wi-Fi status...</Text>
        )}
        <Text style={styles.title}>
          {isOn ? 'Disable' : 'Enable'} NOKIA-45AA_Guest wifi
        </Text>
        <Text style={styles.description}>
          Switching ON enables the NOKIA-45AA_Guest SSID on its matching Wi-Fi
          bands. Switching OFF disables those matching guest network entries.
        </Text>

        {Platform.OS !== 'web' && !isRouterPasswordLoaded && (
          <Text style={styles.credentialMessage}>
            Loading saved router access...
          </Text>
        )}
        {Platform.OS !== 'web' &&
          isRouterPasswordLoaded &&
          !routerPassword && (
            <View style={styles.credentialSetup}>
              <Text style={styles.credentialTitle}>Connect to your router</Text>
              <Text style={styles.credentialMessage}>
                Enter the router password once. It will be stored securely on
                this Android device.
              </Text>
              <TextInput
                accessibilityLabel="Router password"
                autoCapitalize="none"
                autoCorrect={false}
                onChangeText={setRouterPasswordInput}
                onSubmitEditing={() => void saveRouterPassword()}
                placeholder="Router password"
                placeholderTextColor="#7E879A"
                secureTextEntry
                style={styles.credentialInput}
                value={routerPasswordInput}
              />
              <Pressable
                accessibilityRole="button"
                onPress={() => void saveRouterPassword()}
                style={styles.credentialButton}
              >
                <Text style={styles.credentialButtonLabel}>
                  Save securely and connect
                </Text>
              </Pressable>
            </View>
          )}

        <View style={styles.buttonWrap}>
          {isButtonBusy && (
            <Animated.View
              accessible={false}
              pointerEvents="none"
              style={[
                styles.progressRing,
                { transform: [{ rotate: buttonProgressRotation }] },
              ]}
            />
          )}
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`Turn ${isOn ? 'off' : 'on'}`}
            accessibilityState={{ checked: isOn, busy: isButtonBusy }}
            disabled={
              isButtonBusy || (Platform.OS !== 'web' && !routerPassword)
            }
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
        </View>
        {Platform.OS !== 'web' && routerPassword && (
          <Pressable
            accessibilityRole="button"
            onPress={() => void changeRouterPassword()}
            style={styles.changePasswordButton}
          >
            <Text style={styles.changePasswordLabel}>
              Change saved router password
            </Text>
          </Pressable>
        )}

        <View style={styles.status}>
          <View style={[styles.statusDot, isOn && styles.statusDotOn]} />
          <Text style={styles.statusText}>
            {isOn ? 'IT’S ON' : 'IT’S OFF'}
          </Text>
        </View>

        {requestError !== null && (
          <Text accessibilityRole="alert" style={styles.errorText}>
            {requestError}
          </Text>
        )}

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
  credentialSetup: {
    width: '100%',
    marginBottom: 28,
    padding: 18,
    borderRadius: 16,
    backgroundColor: '#171E2E',
  },
  credentialTitle: {
    color: '#F5F7FC',
    fontSize: 18,
    fontWeight: '700',
    textAlign: 'center',
  },
  credentialMessage: {
    color: '#A7AEC0',
    fontSize: 14,
    lineHeight: 21,
    marginTop: 10,
    textAlign: 'center',
  },
  credentialInput: {
    minHeight: 48,
    marginTop: 16,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: '#394255',
    borderRadius: 10,
    color: '#F5F7FC',
    fontSize: 16,
  },
  credentialButton: {
    minHeight: 48,
    marginTop: 12,
    borderRadius: 10,
    backgroundColor: '#086CFA',
    alignItems: 'center',
    justifyContent: 'center',
  },
  credentialButtonLabel: {
    color: '#FFFFFF',
    fontSize: 15,
    fontWeight: '700',
  },
  changePasswordButton: {
    paddingVertical: 12,
  },
  changePasswordLabel: {
    color: '#91B9FF',
    fontSize: 14,
  },
  buttonWrap: {
    width: 248,
    height: 248,
    alignItems: 'center',
    justifyContent: 'center',
  },
  progressRing: {
    position: 'absolute',
    width: 244,
    height: 244,
    borderRadius: 122,
    borderWidth: 4,
    borderColor: '#30394C',
    borderTopColor: '#78F0C0',
    borderRightColor: '#78F0C0',
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
  errorText: {
    color: '#FF9B9B',
    fontSize: 13,
    lineHeight: 19,
    paddingVertical: 8,
  },
});
