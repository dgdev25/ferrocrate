export type CommandResult = {
  ok: boolean;
  code: number;
  stdout: string;
  stderr: string;
};

export type DesktopSnapshot = {
  runtime: CommandResult;
  containers: CommandResult;
  images: CommandResult;
};
