import { app } from './api';

// The entry point, separate from the app. Its only job here is to make `api.ts`
// a file that something imports: with an inbound edge, a namespace object or a
// computed member access could in principle reach `sanitizeUserInput` without
// ever spelling its name, and the finding's confidence has to say so.
app.listen(Number(process.env.PORT ?? 3000));
