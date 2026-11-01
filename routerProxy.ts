export function getProxyUrl(_path: string): string {
  throw new Error('Proxy requests are unavailable on this platform.');
}

export function getProxyErrorMessage(): string {
  return 'The web proxy is unavailable on this platform.';
}
