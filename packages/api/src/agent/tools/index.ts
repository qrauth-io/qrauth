import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Tool definitions for Claude API
export const TOOL_DEFINITIONS = [
  {
    name: 'query_scan_patterns',
    description: 'Query scan event patterns aggregated by time period, QR code, IP hash, or organization',
    input_schema: {
      type: 'object' as const,
      properties: {
        timeRange: { type: 'string', enum: ['24h', '7d', '30d'], description: 'Time range to query' },
        groupBy: { type: 'string', enum: ['hour', 'day', 'qrCode', 'ipHash', 'organization'], description: 'Aggregation dimension' },
        limit: { type: 'number', description: 'Max results (default 20)' },
      },
      required: ['timeRange'],
    },
  },
  {
    name: 'query_fraud_incidents',
    description: 'Query fraud incident patterns with type/severity breakdown and false positive rates',
    input_schema: {
      type: 'object' as const,
      properties: {
        timeRange: { type: 'string', enum: ['24h', '7d', '30d'] },
        groupBy: { type: 'string', enum: ['type', 'severity', 'day', 'organization'] },
      },
      required: ['timeRange'],
    },
  },
  {
    name: 'query_login_events',
    description: 'Query login event patterns — failed attempts, new countries, provider usage',
    input_schema: {
      type: 'object' as const,
      properties: {
        timeRange: { type: 'string', enum: ['24h', '7d', '30d'] },
        groupBy: { type: 'string', enum: ['user', 'country', 'provider', 'device', 'success'] },
      },
      required: ['timeRange'],
    },
  },
  {
    name: 'query_org_activity',
    description: 'Query per-organization activity metrics: QR codes, scans, last activity, engagement',
    input_schema: {
      type: 'object' as const,
      properties: {
        timeRange: { type: 'string', enum: ['24h', '7d', '30d'] },
        sortBy: { type: 'string', enum: ['scans', 'qrcodes', 'lastActivity'] },
        limit: { type: 'number' },
      },
      required: ['timeRange'],
    },
  },
  {
    name: 'query_feature_snapshots',
    description: 'Query pre-computed feature vectors and analytics snapshots',
    input_schema: {
      type: 'object' as const,
      properties: {
        type: { type: 'string', description: 'Snapshot type: scan_features, daily_summary, agent_report' },
        entityType: { type: 'string', description: 'Entity type: organization, qrCode, global' },
        entityId: { type: 'string', description: 'Specific entity ID (optional)' },
        limit: { type: 'number' },
      },
      required: ['type'],
    },
  },
  {
    name: 'create_fraud_rule',
    description: 'Create a new dynamic fraud rule that will be evaluated against every scan in real-time',
    input_schema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Unique rule name' },
        description: { type: 'string', description: 'Human-readable description' },
        conditions: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              field: { type: 'string' },
              operator: { type: 'string', enum: ['gt', 'lt', 'gte', 'lte', 'eq', 'neq', 'between', 'in'] },
              value: {},
            },
            required: ['field', 'operator', 'value'],
          },
          description: 'Conditions that must ALL match (AND logic)',
        },
        action: {
          type: 'object',
          properties: {
            deductScore: { type: 'number', description: 'Trust score deduction (5-40)' },
            severity: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
            type: { type: 'string', default: 'PATTERN_ANOMALY' },
            reason: { type: 'string', description: 'Machine-readable reason code' },
          },
          required: ['deductScore', 'severity', 'reason'],
        },
        priority: { type: 'number', description: 'Lower = higher priority (default 100)' },
      },
      required: ['name', 'description', 'conditions', 'action'],
    },
  },
  {
    name: 'write_report',
    description: 'Write a daily analysis report — stored in DB and optionally emailed to admins',
    input_schema: {
      type: 'object' as const,
      properties: {
        title: { type: 'string' },
        sections: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              heading: { type: 'string' },
              content: { type: 'string' },
            },
          },
        },
        severity: { type: 'string', enum: ['info', 'warning', 'critical'], description: 'Overall report severity' },
      },
      required: ['title', 'sections', 'severity'],
    },
  },
  {
    name: 'suggest_code_change',
    description: 'Create a GitHub issue suggesting a code improvement based on your analysis',
    input_schema: {
      type: 'object' as const,
      properties: {
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Detailed description with evidence' },
        labels: { type: 'array', items: { type: 'string' }, description: 'Issue labels' },
      },
      required: ['title', 'body'],
    },
  },
];

// Tool implementations
function getTimeRange(range: string): Date {
  const now = new Date();
  switch (range) {
    case '24h': return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    case '7d': return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    case '30d': return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    default: return new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }
}

export async function executeTool(name: string, input: Record<string, unknown>): Promise<string> {
  try {
    switch (name) {
      case 'query_scan_patterns': {
        const since = getTimeRange(input.timeRange as string);
        const limit = (input.limit as number) || 20;

        if (input.groupBy === 'hour') {
          const scans = await prisma.scan.findMany({
            where: { createdAt: { gte: since } },
            select: { createdAt: true, trustScore: true, proxyDetected: true },
            orderBy: { createdAt: 'desc' },
            take: 1000,
          });
          // Group by hour
          const hourly: Record<string, { count: number; avgTrust: number; proxied: number }> = {};
          for (const s of scans) {
            const hour = s.createdAt.toISOString().slice(0, 13);
            if (!hourly[hour]) hourly[hour] = { count: 0, avgTrust: 0, proxied: 0 };
            hourly[hour].count++;
            hourly[hour].avgTrust += s.trustScore;
            if (s.proxyDetected) hourly[hour].proxied++;
          }
          for (const h of Object.values(hourly)) h.avgTrust = Math.round(h.avgTrust / h.count);
          return JSON.stringify({ totalScans: scans.length, hourly: Object.entries(hourly).slice(0, limit).map(([h, d]) => ({ hour: h, ...d })) });
        }

        if (input.groupBy === 'organization') {
          const orgs = await prisma.scan.groupBy({
            by: ['qrCodeId'],
            where: { createdAt: { gte: since } },
            _count: true,
            _avg: { trustScore: true },
            orderBy: { _count: { qrCodeId: 'desc' } },
            take: limit,
          });
          return JSON.stringify({ groups: orgs });
        }

        // Default: summary
        const [total, avgTrust, proxyCount] = await Promise.all([
          prisma.scan.count({ where: { createdAt: { gte: since } } }),
          prisma.scan.aggregate({ where: { createdAt: { gte: since } }, _avg: { trustScore: true } }),
          prisma.scan.count({ where: { createdAt: { gte: since }, proxyDetected: true } }),
        ]);
        return JSON.stringify({ totalScans: total, avgTrustScore: Math.round(avgTrust._avg.trustScore ?? 100), proxiedScans: proxyCount });
      }

      case 'query_fraud_incidents': {
        const since = getTimeRange(input.timeRange as string);
        if (input.groupBy === 'type') {
          const groups = await prisma.fraudIncident.groupBy({
            by: ['type'],
            where: { createdAt: { gte: since } },
            _count: true,
          });
          const resolved = await prisma.fraudIncident.count({ where: { createdAt: { gte: since }, resolved: true } });
          const total = await prisma.fraudIncident.count({ where: { createdAt: { gte: since } } });
          return JSON.stringify({ byType: groups, total, resolved, falsePositiveRate: total > 0 ? Math.round((resolved / total) * 100) : 0 });
        }
        if (input.groupBy === 'severity') {
          const groups = await prisma.fraudIncident.groupBy({
            by: ['severity'],
            where: { createdAt: { gte: since } },
            _count: true,
          });
          return JSON.stringify({ bySeverity: groups });
        }
        // Default
        const incidents = await prisma.fraudIncident.findMany({
          where: { createdAt: { gte: since } },
          include: { qrCode: { select: { token: true, organizationId: true } } },
          orderBy: { createdAt: 'desc' },
          take: 50,
        });
        return JSON.stringify({ count: incidents.length, incidents: incidents.map((i) => ({ type: i.type, severity: i.severity, resolved: i.resolved, details: i.details, createdAt: i.createdAt })) });
      }

      case 'query_login_events': {
        const since = getTimeRange(input.timeRange as string);
        if (input.groupBy === 'country') {
          const groups = await prisma.loginEvent.groupBy({
            by: ['ipCountry'],
            where: { createdAt: { gte: since }, ipCountry: { not: null } },
            _count: true,
            orderBy: { _count: { ipCountry: 'desc' } },
            take: 20,
          });
          return JSON.stringify({ byCountry: groups });
        }
        if (input.groupBy === 'success') {
          const [success, failed] = await Promise.all([
            prisma.loginEvent.count({ where: { createdAt: { gte: since }, success: true } }),
            prisma.loginEvent.count({ where: { createdAt: { gte: since }, success: false } }),
          ]);
          return JSON.stringify({ successful: success, failed, failRate: success + failed > 0 ? Math.round((failed / (success + failed)) * 100) : 0 });
        }
        const total = await prisma.loginEvent.count({ where: { createdAt: { gte: since } } });
        const failed = await prisma.loginEvent.count({ where: { createdAt: { gte: since }, success: false } });
        return JSON.stringify({ total, failed });
      }

      case 'query_org_activity': {
        const since = getTimeRange(input.timeRange as string);
        const orgs = await prisma.organization.findMany({
          select: {
            id: true,
            name: true,
            plan: true,
            createdAt: true,
            _count: { select: { qrCodes: true, memberships: true } },
          },
          take: (input.limit as number) || 20,
        });

        const result = await Promise.all(orgs.map(async (org) => {
          const scanCount = await prisma.scan.count({
            where: { qrCode: { organizationId: org.id }, createdAt: { gte: since } },
          });
          const lastScan = await prisma.scan.findFirst({
            where: { qrCode: { organizationId: org.id } },
            orderBy: { createdAt: 'desc' },
            select: { createdAt: true },
          });
          return {
            id: org.id,
            name: org.name,
            plan: org.plan,
            qrCodes: org._count.qrCodes,
            members: org._count.memberships,
            scansInPeriod: scanCount,
            lastScanAt: lastScan?.createdAt || null,
            daysSinceCreation: Math.floor((Date.now() - org.createdAt.getTime()) / 86400000),
          };
        }));

        return JSON.stringify({ organizations: result });
      }

      case 'query_feature_snapshots': {
        const snapshots = await prisma.analyticsSnapshot.findMany({
          where: {
            type: input.type as string,
            ...(input.entityType ? { entityType: input.entityType as string } : {}),
            ...(input.entityId ? { entityId: input.entityId as string } : {}),
          },
          orderBy: { createdAt: 'desc' },
          take: (input.limit as number) || 10,
        });
        return JSON.stringify({ count: snapshots.length, snapshots });
      }

      case 'create_fraud_rule': {
        const action = input.action as Record<string, unknown>;
        const rule = await prisma.fraudRule.create({
          data: {
            name: input.name as string,
            description: input.description as string,
            conditions: input.conditions as object,
            action: { ...action, type: (action.type as string) || 'PATTERN_ANOMALY' },
            priority: (input.priority as number) || 100,
            source: 'agent',
          },
        });
        return JSON.stringify({ created: true, ruleId: rule.id, name: rule.name });
      }

      case 'write_report': {
        const report = await prisma.analyticsSnapshot.create({
          data: {
            type: 'agent_report',
            entityType: 'global',
            entityId: 'global',
            periodStart: new Date(Date.now() - 24 * 60 * 60 * 1000),
            periodEnd: new Date(),
            data: { title: input.title as string, sections: input.sections as object, severity: input.severity as string } as object,
          },
        });

        // Send email if configured
        if (process.env.ADMIN_EMAIL) {
          const { sendDailyReportEmail } = await import('../../lib/email.js');
          await sendDailyReportEmail(
            process.env.ADMIN_EMAIL,
            input.title as string,
            input.sections as Array<{ heading: string; content: string }>,
            input.severity as string,
          );
        }

        return JSON.stringify({ stored: true, reportId: report.id, emailed: !!process.env.ADMIN_EMAIL });
      }

      case 'suggest_code_change': {
        // For now, store as an analytics snapshot. In production, this would use the GitHub API.
        await prisma.analyticsSnapshot.create({
          data: {
            type: 'code_suggestion',
            entityType: 'global',
            entityId: 'global',
            periodStart: new Date(),
            periodEnd: new Date(),
            data: { title: input.title as string, body: input.body as string, labels: (input.labels as string[]) || [] } as object,
          },
        });
        return JSON.stringify({ stored: true, message: 'Code suggestion recorded. Review in dashboard.' });
      }

      default:
        return JSON.stringify({ error: `Unknown tool: ${name}` });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return JSON.stringify({ error: message });
  }
}

export async function cleanup() {
  await prisma.$disconnect();
}
