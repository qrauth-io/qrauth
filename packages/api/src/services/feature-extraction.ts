import { Redis } from 'ioredis';
import { redis } from '../lib/cache.js';

/**
 * Keys of the feature vector, in one place. The fraud rule schema
 * (FRAUD_RULE_FEATURE_FIELDS in @qrauth/shared) must list exactly these;
 * a parity test enforces it.
 */
export const FEATURE_KEYS = [
  'scanVelocity5m',
  'scanVelocity1h',
  'ipDispersion1h',
  'hourOfDay',
  'dayOfWeek',
  'isBot',
  'isNewIp',
  'timeSinceLastScan',
  'trustScoreTrend',
] as const;

export type FeatureKey = (typeof FEATURE_KEYS)[number];

export interface FeatureVector {
  scanVelocity5m: number;    // scans of this QR code in the last 5 minutes
  scanVelocity1h: number;    // scans of this QR code in the last hour
  ipDispersion1h: number;    // distinct QR codes scanned from this IP hash in 1 h
  hourOfDay: number;         // UTC
  dayOfWeek: number;         // UTC, 0 = Sunday
  isBot: boolean;
  isNewIp: boolean;
  timeSinceLastScan: number; // seconds; NO_PRIOR_SCAN_SECONDS when none in 24 h
  trustScoreTrend: number;   // mean of the last 20 trust scores
}

// Compile-time check that FEATURE_KEYS and FeatureVector name the same keys.
type SameKeys<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
const FEATURE_KEYS_MATCH_VECTOR: SameKeys<FeatureKey, keyof FeatureVector> = true;
void FEATURE_KEYS_MATCH_VECTOR;

/** timeSinceLastScan sentinel: no scan of this code in the previous 24 h. */
export const NO_PRIOR_SCAN_SECONDS = 999999;

export class FeatureExtractionService {
  private redis: Redis;

  constructor() {
    this.redis = redis;
  }

  async extractFeatures(data: {
    qrCodeId: string;
    clientIpHash: string;
    userAgent?: string;
    trustScore?: number;
    timestamp?: number;
  }): Promise<FeatureVector> {
    const now = data.timestamp || Date.now();
    const nowSec = Math.floor(now / 1000);

    // --- Scan velocity (sorted set with timestamps as scores) ---
    const velKey = `qrauth:vel:${data.qrCodeId}`;
    await this.redis.zadd(velKey, nowSec, `${nowSec}:${Math.random().toString(36).slice(2, 8)}`);
    await this.redis.expire(velKey, 3600); // 1h TTL
    // Remove entries older than 1h
    await this.redis.zremrangebyscore(velKey, 0, nowSec - 3600);

    const fiveMinAgo = nowSec - 300;
    const oneHourAgo = nowSec - 3600;
    const scanVelocity5m = await this.redis.zcount(velKey, fiveMinAgo, '+inf');
    const scanVelocity1h = await this.redis.zcount(velKey, oneHourAgo, '+inf');

    // --- IP dispersion (HyperLogLog of QR codes per IP) ---
    const ipDispKey = `qrauth:ipdisp:${data.clientIpHash}`;
    await this.redis.pfadd(ipDispKey, data.qrCodeId);
    await this.redis.expire(ipDispKey, 3600);
    const ipDispersion1h = await this.redis.pfcount(ipDispKey);

    // --- Time features ---
    const d = new Date(now);
    const hourOfDay = d.getUTCHours();
    const dayOfWeek = d.getUTCDay();

    // --- Bot detection from UA ---
    const ua = data.userAgent || '';
    const isBot = /bot|crawler|spider|scraper|curl|wget|python|java\/|go-http/i.test(ua);

    // --- Is new IP for this QR code ---
    const knownIpKey = `qrauth:knownips:${data.qrCodeId}`;
    const wasKnown = await this.redis.sismember(knownIpKey, data.clientIpHash);
    await this.redis.sadd(knownIpKey, data.clientIpHash);
    await this.redis.expire(knownIpKey, 86400); // 24h
    const isNewIp = !wasKnown;

    // --- Time since last scan ---
    const lastScanKey = `qrauth:lastscan:${data.qrCodeId}`;
    const lastScanStr = await this.redis.get(lastScanKey);
    const timeSinceLastScan = lastScanStr ? nowSec - parseInt(lastScanStr, 10) : NO_PRIOR_SCAN_SECONDS;
    await this.redis.set(lastScanKey, nowSec, 'EX', 86400);

    // --- Trust score trend (rolling list of last 20) ---
    const trendKey = `qrauth:tscore:${data.qrCodeId}`;
    if (data.trustScore !== undefined) {
      await this.redis.lpush(trendKey, data.trustScore.toString());
      await this.redis.ltrim(trendKey, 0, 19);
      await this.redis.expire(trendKey, 86400);
    }
    const trendValues = await this.redis.lrange(trendKey, 0, 19);
    const trustScoreTrend = trendValues.length > 0
      ? trendValues.reduce((sum, v) => sum + parseFloat(v), 0) / trendValues.length
      : 100;

    const features: FeatureVector = {
      scanVelocity5m,
      scanVelocity1h,
      ipDispersion1h,
      hourOfDay,
      dayOfWeek,
      isBot,
      isNewIp,
      timeSinceLastScan,
      trustScoreTrend,
    };
    return features;
  }

  /**
   * Store feature vector in pending list for hourly batch flush.
   */
  async storePendingFeatures(scanId: string, orgId: string, features: FeatureVector): Promise<void> {
    const entry = JSON.stringify({ scanId, orgId, features, ts: Date.now() });
    await this.redis.lpush('qrauth:features:pending', entry);
    await this.redis.ltrim('qrauth:features:pending', 0, 9999);
  }
}
