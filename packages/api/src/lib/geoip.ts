/**
 * Scan place from the client IP, read from a local DB-IP Lite City MMDB file
 * (ADR-0006 D1). The lookup is in memory: no I/O and no external service, so
 * the IP never leaves the process. Callers pass the IP before hashing it and
 * keep only the result.
 *
 * IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
 */
import { readFileSync, statSync } from 'node:fs';
import { isIP } from 'node:net';

import { Reader } from 'mmdb-lib';

export interface ScanPlace {
  /** ISO 3166-1 alpha-2, upper case. */
  readonly country: string | null;
  readonly region: string | null;
  readonly city: string | null;
}

/** The parts of a DB-IP City record that are read. */
interface CityRecord {
  country?: { iso_code?: string };
  subdivisions?: Array<{ names?: { en?: string } }>;
  city?: { names?: { en?: string } };
}

export const NO_PLACE: ScanPlace = Object.freeze({ country: null, region: null, city: null });

/** Column limits on scans.region / scans.city. */
const PLACE_NAME_MAX = 128;
const COUNTRY_CODE = /^[A-Z]{2}$/;
/** How often the file's modification time is checked for a monthly update. */
export const GEOIP_RELOAD_CHECK_MS = 6 * 60 * 60 * 1000;
/** Database types accepted: DB-IP's City Lite and the commercial City editions. */
const ACCEPTED_TYPES = /^DBIP-City/;

function placeName(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed.slice(0, PLACE_NAME_MAX) : null;
}

/** Maps a DB-IP City record to the stored columns. */
export function placeFromRecord(record: CityRecord | null | undefined): ScanPlace {
  if (!record) return NO_PLACE;
  const code = record.country?.iso_code?.toUpperCase();
  const country = code && COUNTRY_CODE.test(code) ? code : null;
  if (!country) return NO_PLACE;
  return {
    country,
    region: placeName(record.subdivisions?.[0]?.names?.en),
    city: placeName(record.city?.names?.en),
  };
}

type Lookup = (ip: string) => CityRecord | null;

/** Opens an MMDB file, checks its type and returns a lookup function. */
export function openCityDatabase(path: string): { lookup: Lookup; databaseType: string; buildEpoch: number } {
  const reader = new Reader(readFileSync(path));
  const databaseType = String(reader.metadata.databaseType);
  if (!ACCEPTED_TYPES.test(databaseType)) {
    throw new Error(`geoip: ${path} is a ${databaseType} database, not DB-IP City`);
  }
  // DB-IP City records are a superset of CityRecord; only these fields are read.
  return { lookup: (ip) => reader.get(ip) as CityRecord | null, databaseType, buildEpoch: Number(reader.metadata.buildEpoch) };
}

interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
}

/**
 * The process-wide lookup. `init` loads the file once at boot; `lookupPlace`
 * is synchronous and never throws. The file is re-opened when its
 * modification time changes; a file that fails to open keeps the old one.
 */
export class GeoIpService {
  private lookup: Lookup | null = null;
  private path: string | undefined;
  private mtimeMs = 0;
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly log: Logger = console) {}

  get enabled(): boolean {
    return this.lookup !== null;
  }

  init(path: string | undefined): void {
    this.path = path;
    if (!path) {
      this.log.warn('[geoip] GEOIP_DB_PATH is not set: scans are recorded without country, region or city');
      return;
    }
    this.load();
    if (!this.timer) {
      this.timer = setInterval(() => this.reloadIfChanged(), GEOIP_RELOAD_CHECK_MS);
      this.timer.unref();
    }
  }

  /** Re-opens the file when its modification time changed. */
  reloadIfChanged(): void {
    if (!this.path) return;
    try {
      if (statSync(this.path).mtimeMs !== this.mtimeMs) this.load();
    } catch (err) {
      this.log.warn(`[geoip] cannot stat ${this.path}: ${(err as Error).message}; keeping the loaded database`);
    }
  }

  private load(): void {
    const path = this.path!;
    try {
      const mtimeMs = statSync(path).mtimeMs;
      const db = openCityDatabase(path);
      this.lookup = db.lookup;
      this.mtimeMs = mtimeMs;
      // mmdb-lib gives the build time as a Date; Number() is its epoch in ms.
      const built = Number.isFinite(db.buildEpoch) ? new Date(db.buildEpoch).toISOString().slice(0, 10) : 'unknown';
      this.log.info(`[geoip] loaded ${db.databaseType} built ${built} from ${path}`);
    } catch (err) {
      this.log.warn(
        `[geoip] cannot load ${path}: ${(err as Error).message}; ${this.lookup ? 'keeping the loaded database' : 'scans are recorded without place'}`,
      );
    }
  }

  /** Place for an IP, or NO_PLACE (no database, invalid or private address, not found). */
  lookupPlace(ip: string | undefined | null): ScanPlace {
    if (!this.lookup || !ip || isIP(ip) === 0) return NO_PLACE;
    try {
      return placeFromRecord(this.lookup(ip));
    } catch {
      return NO_PLACE;
    }
  }

  /** Test seam: replaces the lookup. */
  setLookupForTests(lookup: Lookup | null): void {
    this.lookup = lookup;
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

/** The API process's instance, initialised in server.ts. */
export const geoIp = new GeoIpService();
