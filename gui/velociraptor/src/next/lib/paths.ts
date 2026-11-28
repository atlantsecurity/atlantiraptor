// VFS paths travel in console URLs with "%" written as "-" so they
// survive routers and proxies (the same encoding the server uses).
export function encodePathInURL(path: string): string {
  return encodeURI(path.replace(/-/g, '%2d')).replace(/%/g, '-');
}

export function decodePathInURL(path: string): string {
  return decodeURI(path.replace(/-/g, '%'));
}
