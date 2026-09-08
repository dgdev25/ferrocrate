/** Preserve terminal byte order across asynchronous native and HTTP transports. */
export function createTerminalCommandQueue() {
  let pending = Promise.resolve();
  let inputFailed = false;
  let inputFailure;

  return {
    invoke(command, operation) {
      if (!['start_terminal', 'write_terminal', 'close_terminal'].includes(command)) {
        return operation();
      }

      const result = pending.then(async () => {
        if (command === 'write_terminal' && inputFailed) throw inputFailure;
        try {
          const value = await operation();
          if (command === 'start_terminal') {
            inputFailed = false;
            inputFailure = undefined;
          }
          return value;
        } catch (error) {
          if (command === 'write_terminal') {
            // Sending the rest of a partially delivered command can execute a
            // different command. Require a fresh shell before accepting input.
            inputFailed = true;
            inputFailure = error;
          }
          throw error;
        }
      });
      // A rejected operation must not prevent closing or starting a fresh shell.
      pending = result.then(() => undefined, () => undefined);
      return result;
    },
  };
}
