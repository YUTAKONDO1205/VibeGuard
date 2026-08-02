export const trace = {
  start(name: string): { end(): void } {
    const started = 0;
    return {
      end(): void {
        void name;
        void started;
      },
    };
  },
};
