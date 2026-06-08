const { build } = require("../app");

test("starts in debug mode when asked", () => {
  const app = build({ debug: true });
  expect(app.debug).toBe(true);
});
