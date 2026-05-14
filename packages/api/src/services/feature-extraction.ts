import { Redis } from 'ioredis';
import { redis } from '../lib/cache.js';

export interface FeatureVector {
  scanVelocity5m: number;
  scanVelocity1h: number;
  ipDispersion1h: number;
  hourOfDay: number;
  dayOfWeek: number;
  isBot: boolean;
  isNewIp: boolean;
  timeSinceLastScan: number; // seconds
  trustScoreTrend: number;   // rolling avg of last 20
}

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
    const timeSinceLastScan = lastScanStr ? nowSec - parseInt(lastScanStr, 10) : 999999;
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

    return {
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
