export function getProxyUrl(_path: string): string {
  throw new Error('Proxy requests are not available in the Android build.');
}

export function getProxyErrorMessage(): string {
  return 'Proxy requests are not available in the Android build.';
}
