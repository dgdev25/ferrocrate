import { createElement as h } from 'react';
import { formatImageCreated } from './imageView.mjs';
import { Icon } from './iconSystem.mjs';
import { groupContainers, containerRemoveAvailability, statusLabel, statusTone } from './forgeShell.mjs';

// Ownership persists independently of current attachments; shared resources remain visible
// in every attached workspace as well as the owning workspace.
export function workspaceGroups(rows, volumes, networks, allRows = rows, { search = "", status = "all" } = {}) {
  const groups = groupContainers(rows);
  const owner = resource => {
    const value = resource.labels?.['com.docker.compose.project'];
    return typeof value === 'string' && value.trim() ? value : undefined;
  };
  for (const resource of [...volumes, ...networks]) {
    const name = owner(resource);
    const populated = allRows.some(row => row.composeProject === name);
    const query = search.trim().toLowerCase();
    const matches = !query || name?.toLowerCase().includes(query) || resource.name.toLowerCase().includes(query);
    if (name && !populated && matches && status === "all" && !groups.some(group => group.compose && group.name === name)) {
      groups.push({ name, compose: true, rows: [], running: 0 });
    }
  }
  return groups.map(group => {
    const ids = new Set(allRows.filter(row => group.compose ? row.composeProject === group.name : !row.composeProject).map(row => row.id));
    return {
      ...group,
      volumes: volumes.filter(volume => (group.compose && owner(volume) === group.name) || volume.mounts.some(mount => ids.has(mount.container_id))),
      networks: networks.filter(network => (group.compose && owner(network) === group.name) || network.containers.some(container => ids.has(container.container_id))),
    };
  });
}

export function ServiceActions({ row, busy, onAction, onInspect }) {
  const running = row.state === 'running';
  return h('div', { className: 'service-actions' },
    h('button', { className: 'btn btn-secondary', disabled: busy, 'aria-label': `${running ? 'Stop' : 'Start'} ${row.name}`, onClick: () => onAction(running ? 'stop_container' : 'start_container', running ? 'Container Stop' : 'Container Start', row.id) }, h(Icon, { name: running ? 'stop' : 'play', size: 14 }), running ? 'Stop' : 'Start'),
    h('button', { className: 'btn btn-ghost', disabled: busy, 'aria-label': `Logs for ${row.name}`, onClick: () => onInspect(row.id, 'logs') }, h(Icon, { name: 'terminal', size: 14 }), 'Logs'),
    h('button', { className: 'btn btn-ghost', disabled: busy || !running, title: running ? undefined : 'Start this service to open a terminal', 'aria-label': `Terminal for ${row.name}`, onClick: () => onInspect(row.id, 'terminal') }, h(Icon, { name: 'terminal', size: 14 }), 'Terminal'),
  );
}

export function WorkspaceCard({ group, selectedId, busy, onAction, onInspect }) {
  return h('article', { className: 'workspace-card', 'aria-label': `${group.name} workspace` },
    h('header', { className: 'workspace-card-head' },
      h('span', { className: 'workspace-emblem', 'aria-hidden': true }, h(Icon, { name: group.compose ? 'compose' : 'box', size: 22 })),
      h('div', null, h('p', { className: 'eyebrow' }, group.compose ? 'Compose workspace' : 'Independent services'), h('h2', null, group.name)),
      h('span', { className: 'workspace-summary' }, `${group.rows.length} services · ${group.running} running`)),
    h('div', { className: 'workspace-services' }, group.rows.map(row => {
      const remove = containerRemoveAvailability(row);
      return h('div', { key: row.id, className: `workspace-service${selectedId === row.id ? ' selected' : ''}` },
        h('div', { className: 'service-identity' },
          h('button', { className: 'service-name', onClick: () => onInspect(row.id, 'inspect'), 'aria-label': `Inspect ${row.name}` }, row.composeService || row.name),
          h('span', { className: 'service-image mono', title: row.image }, row.image),
          row.composeService ? h('span', { className: 'service-runtime-name mono' }, row.name) : null),
        h('div', { className: 'service-state' }, h('span', { className: `container-status ${statusTone(row)}` }, h('i'), statusLabel(row)), h('span', { className: 'mono service-ports' }, row.ports)),
        h('div', { className: 'service-metrics mono' }, h('span', null, row.cpu ? `CPU ${row.cpu}` : 'CPU pending'), h('span', null, row.memory ? `Memory ${row.memory}` : 'Memory pending'), h('span', null, `Started ${row.startedAt ? formatImageCreated(row.startedAt) : '—'}`)),
        h(ServiceActions, { row, busy, onAction, onInspect }),
        h('details', { className: 'row-menu service-menu' }, h('summary', { 'aria-label': `More actions for ${row.name}` }, h(Icon, { name: 'more', size: 16 })),
          h('div', { className: 'overflow-menu' }, h('button', { className: 'danger-action', disabled: busy || !remove.allowed, title: remove.reason || undefined, onClick: () => onAction('remove_container', 'Container Remove', row.id) }, 'Remove container'))));
    })),
    h('footer', { className: 'workspace-resources' },
      h('span', { className: 'resource-label' }, 'Workspace resources'),
      ...group.volumes.map(volume => h('span', { className: 'resource-token', key: `volume:${volume.name}`, title: `Volume: ${volume.name}` }, h(Icon, { name: 'disk', size: 14 }), volume.name)),
      ...group.networks.map(network => h('span', { className: 'resource-token', key: `network:${network.name}`, title: `Network: ${network.name}` }, h(Icon, { name: 'globe', size: 14 }), network.name)),
      !group.volumes.length && !group.networks.length ? h('span', { className: 'muted' }, 'No attached volumes or networks reported') : null),
  );
}
