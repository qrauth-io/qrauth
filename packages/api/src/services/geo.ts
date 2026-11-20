import type { PrismaClient, QRCode } from '@prisma/client';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EARTH_RADIUS_M = 6_371_000;

// Geohash base32 alphabet (no 'a', 'i', 'l', 'o' — standard Niemeyer encoding)
const BASE32_CHARS = '0123456789bcdefghjkmnpqrstuvwxyz';

// ---------------------------------------------------------------------------
// Pure math helpers
// ---------------------------------------------------------------------------

function toRadians(degrees: number): number {
  return (degrees * Math.PI) / 180;
}

/**
 * Haversine great-circle distance between two WGS-84 coordinate pairs.
 * Returns the straight-line distance in metres.
 */
function haversineDistance(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number,
): number {
  const dLat = toRadians(lat2 - lat1);
  const dLng = toRadians(lng2 - lng1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(dLng / 2) *
      Math.sin(dLng / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return EARTH_RADIUS_M * c;
}

/**
 * Approximate the bounding-box delta for a given radius in metres.
 * Used to generate a cheap pre-filter before the exact Haversine check.
 */
function radiusToBoundingBoxDelta(lat: number, radiusM: number) {
  const latDelta = (radiusM / EARTH_RADIUS_M) * (180 / Math.PI);
  // Longitude degrees per metre shrink as latitude increases.
  const lngDelta =
    (radiusM / (EARTH_RADIUS_M * Math.cos(toRadians(lat)))) * (180 / Math.PI);
  return { latDelta, lngDelta };
}

// ---------------------------------------------------------------------------
// GeoService
// ---------------------------------------------------------------------------

export interface ProximityResult {
  matched: boolean;
  distanceM: number;
}

export class GeoService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Check whether a client position falls within a QR code's geo-fence.
   *
   * @param qrLat      - Registered latitude of the QR code.
   * @param qrLng      - Registered longitude of the QR code.
   * @param qrRadiusM  - Geo-fence radius in metres.
   * @param clientLat  - Client-reported latitude.
   * @param clientLng  - Client-reported longitude.
   */
  checkProximity(
    qrLat: number,
    qrLng: number,
    qrRadiusM: number,
    clientLat: number,
    clientLng: number,
  ): ProximityResult {
    const distanceM = haversineDistance(qrLat, qrLng, clientLat, clientLng);
    return { matched: distanceM <= qrRadiusM, distanceM };
  }

  /**
   * Encode a WGS-84 coordinate pair as a geohash string.
   *
   * Implements the Gustavo Niemeyer base32 geohash algorithm.
   * Precision 7 yields ~76 m × 76 m cells; precision 9 yields ~2.4 m × 4.8 m.
   *
   * @param lat       - Latitude  (−90 … +90).
   * @param lng       - Longitude (−180 … +180).
   * @param precision - Number of geohash characters to return (default 7).
   */
  encodeGeoHash(lat: number, lng: number, precision: number = 7): string {
    if (lat < -90 || lat > 90) {
      throw new Error(`Latitude ${lat} is out of range (−90 … +90).`);
    }
    if (lng < -180 || lng > 180) {
      throw new Error(`Longitude ${lng} is out of range (−180 … +180).`);
    }

    let minLat = -90;
    let maxLat = 90;
    let minLng = -180;
    let maxLng = 180;

    let hash = '';
    let bits = 0;
    let hashValue = 0;
    let isEven = true; // Start with longitude (even bits)

    while (hash.length < precision) {
      if (isEven) {
        // Bisect longitude range.
        const midLng = (minLng + maxLng) / 2;
        if (lng >= midLng) {
          hashValue = (hashValue << 1) | 1;
          minLng = midLng;
        } else {
          hashValue = hashValue << 1;
          maxLng = midLng;
        }
      } else {
        // Bisect latitude range.
        const midLat = (minLat + maxLat) / 2;
        if (lat >= midLat) {
          hashValue = (hashValue << 1) | 1;
          minLat = midLat;
        } else {
          hashValue = hashValue << 1;
          maxLat = midLat;
        }
      }

      isEven = !isEven;
      bits++;

      if (bits === 5) {
        hash += BASE32_CHARS[hashValue];
        bits = 0;
        hashValue = 0;
      }
    }

    return hash;
  }

  /**
   * Find QR codes whose registered position is within radiusM metres of the
   * supplied coordinate pair.
   *
   * The query first applies a cheap bounding-box pre-filter on the indexed
   * latitude/longitude columns, then refines the result set with an exact
   * Haversine check in application code.
   *
   * Only ACTIVE QR codes with a registered position are considered.
   */
  async findNearbyQRCodes(
    lat: number,
    lng: number,
    radiusM: number,
  ): Promise<QRCode[]> {
    const { latDelta, lngDelta } = radiusToBoundingBoxDelta(lat, radiusM);

    // Bounding-box pre-filter — eliminates the vast majority of rows cheaply.
    const candidates = await this.prisma.qRCode.findMany({
      where: {
        status: 'ACTIVE',
        latitude: { gte: lat - latDelta, lte: lat + latDelta },
        longitude: { gte: lng - lngDelta, lte: lng + lngDelta },
      },
    });

    // Exact Haversine refinement.
    return candidates.filter((qr) => {
      if (qr.latitude === null || qr.longitude === null) return false;
      const distanceM = haversineDistance(lat, lng, qr.latitude, qr.longitude);
      return distanceM <= radiusM;
    });
  }
}

// Re-export the pure helper so other services (e.g. FraudDetectionService) can
// use it without going through the class.
export { haversineDistance };
