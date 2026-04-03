import type { PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Homoglyph map — characters that look similar
// ---------------------------------------------------------------------------
const HOMOGLYPHS: Record<string, string[]> = {
  '0': ['o', 'O'],
  'o': ['0', 'O'],
  'O': ['0', 'o'],
  '1': ['l', 'I', 'i'],
  'l': ['1', 'I', 'i'],
  'I': ['1', 'l', 'i'],
  'i': ['1', 'l', 'I'],
  'rn': ['m'],
  'm': ['rn'],
  'vv': ['w'],
  'w': ['vv'],
  'cl': ['d'],
  'd': ['cl'],
  'nn': ['m'],
};

export class DomainService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Extract the domain from a URL, stripping www. prefix
   */
  extractDomain(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  /**
   * Levenshtein distance between two strings
   */
  levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1,
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Normalize a domain by replacing common homoglyphs.
   * "pr0gressnet" -> "progressnet", "progress-net" -> "progressnet"
   */
  normalizeDomain(domain: string): string {
    let normalized = domain.toLowerCase();
    // Remove hyphens (progress-net -> progressnet)
    normalized = normalized.replace(/-/g, '');
    // Replace common homoglyphs
    for (const [char, replacements] of Object.entries(HOMOGLYPHS)) {
      for (const replacement of replacements) {
        normalized = normalized.replace(new RegExp(replacement.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), char);
      }
    }
    return normalized;
  }

  /**
   * Check if two domains are suspiciously similar.
   * Returns a similarity score (0-100) and the type of similarity.
   */
  checkSimilarity(domain1: string, domain2: string): {
    similar: boolean;
    score: number;
    reason?: string;
  } {
    if (domain1 === domain2) return { similar: false, score: 0 }; // Exact match = same domain, not suspicious

    const d1 = this.extractDomain(domain1);
    const d2 = this.extractDomain(domain2);

    if (d1 === d2) return { similar: false, score: 0 };

    // Strip TLD for comparison (.gr, .com, etc.)
    const d1Base = d1.replace(/\.[^.]+$/, '');
    const d2Base = d2.replace(/\.[^.]+$/, '');

    // 1. Homoglyph normalization match
    const n1 = this.normalizeDomain(d1Base);
    const n2 = this.normalizeDomain(d2Base);
    if (n1 === n2) {
      return { similar: true, score: 95, reason: 'homoglyph_match' };
    }

    // 2. Levenshtein distance
    const distance = this.levenshtein(d1Base, d2Base);
    const maxLen = Math.max(d1Base.length, d2Base.length);
    const similarity = 1 - distance / maxLen;

    if (distance <= 1 && maxLen > 3) {
      return { similar: true, score: 90, reason: 'one_char_difference' };
    }
    if (distance <= 2 && maxLen > 5) {
      return { similar: true, score: 80, reason: 'typosquatting' };
    }

    // 3. Substring containment (progressnet vs progressnet-pay)
    if (d1Base.includes(d2Base) || d2Base.includes(d1Base)) {
      if (Math.abs(d1Base.length - d2Base.length) <= 4) {
        return { similar: true, score: 70, reason: 'substring_match' };
      }
    }

    // 4. Hyphen insertion (progressnet vs progress-net)
    if (d1Base.replace(/-/g, '') === d2Base.replace(/-/g, '')) {
      return { similar: true, score: 85, reason: 'hyphen_variation' };
    }

    // 5. General similarity threshold
    if (similarity >= 0.8 && maxLen > 4) {
      return { similar: true, score: Math.round(similarity * 100), reason: 'high_similarity' };
    }

    return { similar: false, score: Math.round(similarity * 100) };
  }

  /**
   * Check a new QR code's destination URL against all existing verified domains.
   * Returns warnings if similar domains are found.
   */
  async checkUrlAgainstVerifiedDomains(
    destinationUrl: string,
    excludeOrgId: string,
  ): Promise<{
    warnings: Array<{
      domain: string;
      verifiedOrgName: string;
      similarity: number;
      reason: string;
    }>;
    isSuspicious: boolean;
  }> {
    const newDomain = this.extractDomain(destinationUrl);

    // Get all organizations with verified domains
    const verifiedOrgs = await this.prisma.organization.findMany({
      where: {
        domainVerified: true,
        domain: { not: null },
        id: { not: excludeOrgId },
      },
      select: { id: true, name: true, domain: true },
    });

    // Also check domains from existing QR codes of verified orgs
    const verifiedQRDomains = await this.prisma.qRCode.findMany({
      where: {
        organization: { domainVerified: true, id: { not: excludeOrgId } },
        status: 'ACTIVE',
      },
      select: {
        destinationUrl: true,
        organization: { select: { name: true } },
      },
      distinct: ['destinationUrl'],
      take: 500,
    });

    const warnings: Array<{
      domain: string;
      verifiedOrgName: string;
      similarity: number;
      reason: string;
    }> = [];

    // Check against verified org domains
    for (const org of verifiedOrgs) {
      if (!org.domain) continue;
      const result = this.checkSimilarity(newDomain, org.domain);
      if (result.similar) {
        warnings.push({
          domain: org.domain,
          verifiedOrgName: org.name,
          similarity: result.score,
          reason: result.reason!,
        });
      }
    }

    // Check against QR code destination domains
    const seenDomains = new Set(verifiedOrgs.map((o) => o.domain));
    for (const qr of verifiedQRDomains) {
      const qrDomain = this.extractDomain(qr.destinationUrl);
      if (seenDomains.has(qrDomain)) continue;
      seenDomains.add(qrDomain);

      const result = this.checkSimilarity(newDomain, qrDomain);
      if (result.similar) {
        warnings.push({
          domain: qrDomain,
          verifiedOrgName: qr.organization.name,
          similarity: result.score,
          reason: result.reason!,
        });
      }
    }

    // Sort by similarity descending
    warnings.sort((a, b) => b.similarity - a.similarity);

    return {
      warnings,
      isSuspicious: warnings.some((w) => w.similarity >= 80),
    };
  }

  /**
   * Generate a domain verification token.
   * The org adds a DNS TXT record: qrauth-verify=<token>
   */
  async generateVerifyToken(orgId: string): Promise<string> {
    const token = randomBytes(16).toString('hex');

    await this.prisma.organization.update({
      where: { id: orgId },
      data: { domainVerifyToken: token },
    });

    return token;
  }

  /**
   * Verify domain ownership by checking DNS TXT records.
   */
  async verifyDomain(orgId: string): Promise<{
    verified: boolean;
    error?: string;
  }> {
    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { domain: true, domainVerifyToken: true },
    });

    if (!org?.domain) return { verified: false, error: 'No domain set on organization' };
    if (!org.domainVerifyToken) return { verified: false, error: 'No verification token generated. Call generate-verify-token first.' };

    try {
      // Use DNS lookup via fetch to a DNS-over-HTTPS provider
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(org.domain)}&type=TXT`,
        { signal: AbortSignal.timeout(5000) },
      );

      if (!res.ok) return { verified: false, error: 'DNS lookup failed' };

      const data = await res.json() as {
        Answer?: Array<{ type: number; data: string }>;
      };

      const txtRecords = (data.Answer || [])
        .filter((r) => r.type === 16) // TXT record type
        .map((r) => r.data.replace(/"/g, ''));

      const expectedValue = `qrauth-verify=${org.domainVerifyToken}`;
      const found = txtRecords.some((txt) => txt.includes(expectedValue));

      if (found) {
        await this.prisma.organization.update({
          where: { id: orgId },
          data: { domainVerified: true },
        });
        return { verified: true };
      }

      return {
        verified: false,
        error: `TXT record "qrauth-verify=${org.domainVerifyToken}" not found for ${org.domain}. Found records: ${txtRecords.join(', ') || 'none'}`,
      };
    } catch (err: any) {
      return { verified: false, error: `DNS lookup error: ${err.message}` };
    }
  }
}
