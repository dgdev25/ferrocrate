export type VolumeMountView = {
  container_name: string;
  destination: string;
  read_write: boolean;
};

export function formatVolumeMount(mount: VolumeMountView): string;
export function volumeIsInUse(volume: { mounts: unknown[] }): boolean;
