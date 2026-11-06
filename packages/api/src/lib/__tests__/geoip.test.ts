import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import { GeoIpService, NO_PLACE, placeFromRecord } from '../geoip.js';

/** ADR-0006 D1: place from a DB-IP City record; the lookup never throws. */

const ATHENS = { country: { iso_code: 'GR' }, subdivisions: [{ names: { en: 'Attica' } }], city: { names: { en: 'Athens' } } };

function quietLog() {
  return { info: vi.fn(), warn: vi.fn() };
}

describe('placeFromRecord', () => {
  it('maps country code, first subdivision and city (English names)', () => {
    expect(placeFromRecord(ATHENS)).toEqual({ country: 'GR', region: 'Attica', city: 'Athens' });
  });

  it('upper-cases the code and drops a record without a valid country', () => {
    expect(placeFromRecord({ country: { iso_code: 'gr' } })).toEqual({ country: 'GR', region: null, city: null });
    expect(placeFromRecord({ country: { iso_code: 'GRC' } })).toBe(NO_PLACE);
    expect(placeFromRecord({ city: { names: { en: 'Athens' } } })).toBe(NO_PLACE);
    expect(placeFromRecord(null)).toBe(NO_PLACE);
  });

  it('trims names and cuts them to the column size', () => {
    const long = 'x'.repeat(300);
    expect(placeFromRecord({ country: { iso_code: 'GR' }, city: { names: { en: `  ${long} ` } } }).city).toHaveLength(128);
    expect(placeFromRecord({ country: { iso_code: 'GR' }, city: { names: { en: '  ' } } }).city).toBeNull();
  });
});

describe('GeoIpService', () => {
  it('without a path: disabled, warns once, every lookup is NO_PLACE', () => {
    const log = quietLog();
    const geo = new GeoIpService(log);
    geo.init(undefined);
    expect(geo.enabled).toBe(false);
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(geo.lookupPlace('62.103.0.1')).toBe(NO_PLACE);
  });

  it('an unreadable or invalid file leaves it disabled and is not fatal', () => {
    const log = quietLog();
    const dir = mkdtempSync(join(tmpdir(), 'geoip-'));
    const bad = join(dir, 'bad.mmdb');
    writeFileSync(bad, 'not an mmdb file');
    const geo = new GeoIpService(log);
    geo.init(bad);
    geo.close();
    expect(geo.enabled).toBe(false);
    expect(log.warn.mock.calls[0][0]).toMatch(/cannot load/);
    new GeoIpService(log).init(join(dir, 'missing.mmdb'));
  });

  it('looks up valid IPs only and never throws', () => {
    const geo = new GeoIpService(quietLog());
    const seen: string[] = [];
    geo.setLookupForTests((ip) => {
      seen.push(ip);
      if (ip === '10.0.0.1') return null;
      if (ip === '1.1.1.1') throw new Error('corrupt');
      return ATHENS;
    });
    expect(geo.lookupPlace('62.103.0.1')).toEqual({ country: 'GR', region: 'Attica', city: 'Athens' });
    expect(geo.lookupPlace('2a02:587::1').country).toBe('GR');
    expect(geo.lookupPlace('10.0.0.1')).toBe(NO_PLACE);
    expect(geo.lookupPlace('1.1.1.1')).toBe(NO_PLACE);
    expect(geo.lookupPlace('not-an-ip')).toBe(NO_PLACE);
    expect(geo.lookupPlace(undefined)).toBe(NO_PLACE);
    expect(seen).toEqual(['62.103.0.1', '2a02:587::1', '10.0.0.1', '1.1.1.1']);
  });

  it('keeps the loaded database when a reload fails', () => {
    const log = quietLog();
    const dir = mkdtempSync(join(tmpdir(), 'geoip-'));
    const file = join(dir, 'db.mmdb');
    writeFileSync(file, 'garbage');
    const geo = new GeoIpService(log);
    geo.init(file);
    geo.close();
    geo.setLookupForTests(() => ATHENS);
    writeFileSync(file, 'still garbage, newer mtime');
    geo.reloadIfChanged();
    expect(geo.enabled).toBe(true);
    expect(geo.lookupPlace('62.103.0.1').city).toBe('Athens');
    expect(log.warn.mock.calls.at(-1)?.[0]).toMatch(/keeping the loaded database/);
  });
});

// A real DB-IP file, when one is available locally (not in CI: the file is
// 127 MB and never committed). GEOIP_TEST_DB=/path/to/dbip-city-lite.mmdb
describe.runIf(!!process.env.GEOIP_TEST_DB)('with a real DB-IP City Lite file', () => {
  it('resolves public IPv4 and IPv6 addresses and nothing for private ones', () => {
    const geo = new GeoIpService(quietLog());
    geo.init(process.env.GEOIP_TEST_DB);
    geo.close();
    // Exact places change month to month; a country code is enough here.
    expect(geo.lookupPlace('8.8.8.8').country).toMatch(/^[A-Z]{2}$/);
    expect(geo.lookupPlace('2001:4860:4860::8888').country).toMatch(/^[A-Z]{2}$/);
    expect(geo.lookupPlace('192.168.1.1')).toEqual(NO_PLACE);
    expect(geo.lookupPlace('127.0.0.1')).toEqual(NO_PLACE);
  });
});
