// A barrel. `export *` produces no import edge at all — the indexer's JS_IMPORT
// requires the `import` keyword — so a rule that follows only the import graph
// sees this file as reaching nothing, and every route below it as unmounted.
// That is the exact false positive VG-SMELL-052 shipped.
export * from './billing-routes';
