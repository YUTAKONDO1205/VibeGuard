// FALSE-POSITIVE CONTROL. A page, not an endpoint.
//
// It is under `pages/`, it default-exports a function, and it must NOT become a
// route binding: only `pages/api/**` is an API route in Next.js, and treating
// every page component as a handler would put the entire UI of every Next.js
// project into the route-handler population that VG-SMELL-010/011/013 read.

export default function Home() {
  return null;
}
