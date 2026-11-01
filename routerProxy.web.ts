const proxyBaseUrl = 'http://127.0.0.1:3001';

export function getProxyUrl(path: string): string {
  return new URL(path, proxyBaseUrl).toString();
}

export function getProxyErrorMessage(): string {
  return 'Cannot reach the local router proxy. Start it with "npm run proxy" and keep it running.';
}
