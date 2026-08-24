export function formatVolumeMount(mount) {
  return `${mount.container_name} → ${mount.destination} (${mount.read_write ? "rw" : "ro"})`;
}

export function volumeIsInUse(volume) {
  return volume.mounts.length > 0;
}
