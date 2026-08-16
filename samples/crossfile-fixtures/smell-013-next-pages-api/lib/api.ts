// FALSE-POSITIVE CONTROL. A client, not an endpoint.
//
// The word `api` is in the file NAME rather than in a `pages/api` directory, so
// the convention does not apply. A predicate that matched on the substring would
// turn every HTTP client wrapper in every project into a route registration.

export default function apiClient(path: string): Promise<Response> {
  return fetch(path);
}
