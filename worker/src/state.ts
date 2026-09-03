/**
 * Pure state-transition logic for `domain_check_state`. No I/O — the scheduler
 * reads the previous row, calls this, and persists the result in the same
 * batch as the check_result.
 *
 * `changed` means the status transitioned relative to a known previous state.
 * A first-ever observation is not a transition (so it won't fire an alert in
 * M4), but it is still persisted.
 */

export type Status = "ok" | "info" | "warn" | "unknown" | "crit";

export interface StateRow {
  status: Status;
  score: number | null;
  /** When the current status began. */
  since: string;
  /** Last time this check was observed `ok`. */
  lastOkAt: string | null;
  /** Consecutive observations at the current status (hysteresis input). */
  consecutiveCount: number;
}

export interface Observation {
  status: Status;
  score: number | null;
  observedAt: string;
}

export function nextState(
  prev: StateRow | undefined,
  obs: Observation,
): { row: StateRow; changed: boolean; firstSeen: boolean } {
  if (!prev) {
    return {
      firstSeen: true,
      changed: false,
      row: {
        status: obs.status,
        score: obs.score,
        since: obs.observedAt,
        lastOkAt: obs.status === "ok" ? obs.observedAt : null,
        consecutiveCount: 1,
      },
    };
  }

  const lastOkAt = obs.status === "ok" ? obs.observedAt : prev.lastOkAt;

  if (prev.status === obs.status) {
    return {
      firstSeen: false,
      changed: false,
      row: {
        status: prev.status,
        score: obs.score,
        since: prev.since,
        lastOkAt,
        consecutiveCount: prev.consecutiveCount + 1,
      },
    };
  }

  return {
    firstSeen: false,
    changed: true,
    row: {
      status: obs.status,
      score: obs.score,
      since: obs.observedAt,
      lastOkAt,
      consecutiveCount: 1,
    },
  };
}

const RANK: Record<Status, number> = {
  ok: 0,
  info: 1,
  warn: 2,
  unknown: 3,
  crit: 4,
};

export function worstStatus(statuses: Status[]): Status {
  let worst: Status = "ok";
  for (const s of statuses) if (RANK[s] > RANK[worst]) worst = s;
  return worst;
}

/** now + interval, spread by up to `jitterFraction` of the interval. */
export function nextCheckAt(
  now: Date,
  intervalSeconds: number,
  jitterFraction = 0,
): string {
  const jitter = intervalSeconds * jitterFraction * Math.random();
  return new Date(now.getTime() + (intervalSeconds + jitter) * 1000).toISOString();
}

/** Interval-aligned timestamp for the slot `now` falls in. */
export function slotFor(now: Date, intervalSeconds: number): string {
  const ms = intervalSeconds * 1000;
  return new Date(Math.floor(now.getTime() / ms) * ms).toISOString();
}
