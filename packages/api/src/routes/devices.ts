import type { FastifyInstance } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { authorize } from '../middleware/authorize.js';
import { DeviceService } from '../services/device.js';
import { DevicePolicyService } from '../services/device-policy.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { updateDeviceSchema, updateDevicePolicySchema } from '@qrauth/shared';

export default async function deviceRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;
  const deviceService = new DeviceService(fastify.prisma);
  const policyService = new DevicePolicyService(fastify.prisma);

  // -------------------------------------------------------------------------
  // GET / — List user's trusted devices
  // -------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const devices = await deviceService.listDevices(request.user!.id);
    return reply.send({ data: devices });
  });

  // -------------------------------------------------------------------------
  // GET /current — Identify the current request's device
  // -------------------------------------------------------------------------

  fastify.get('/current', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const meta = await collectRequestMetadata(request);
    const device = await deviceService.getCurrentDevice(request.user!.id, meta);

    if (!device) {
      return reply.send({ device: null });
    }

    return reply.send({
      device: {
        ...device,
        passkeyCount: device._count?.passkeys ?? 0,
        _count: undefined,
      },
    });
  });

  // -------------------------------------------------------------------------
  // PATCH /:id — Update device name or trust level
  // -------------------------------------------------------------------------

  fastify.patch('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
    preValidation: zodValidator({ body: updateDeviceSchema }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { name?: string; trustLevel?: 'TRUSTED' | 'SUSPICIOUS' };

    const device = await deviceService.updateDevice(id, request.user!.id, body);

    if (!device) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Device not found.',
      });
    }

    return reply.send({ device });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id — Revoke a device (and its linked passkeys)
  // -------------------------------------------------------------------------

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const result = await deviceService.revokeDevice(id, request.user!.id);

    if (!result) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Device not found.',
      });
    }

    return reply.send({ message: 'Device revoked.' });
  });

  // -------------------------------------------------------------------------
  // POST /:id/revoke — Mark a device as REVOKED (explicit revocation action)
  // -------------------------------------------------------------------------

  fastify.post('/:id/revoke', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const result = await deviceService.revokeDevice(id, request.user!.id);

    if (!result) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Device not found.',
      });
    }

    return reply.send({ message: 'Device revoked.' });
  });

  // -------------------------------------------------------------------------
  // POST /:id/reverify — Transition a SUSPICIOUS device back to TRUSTED
  // -------------------------------------------------------------------------

  fastify.post('/:id/reverify', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const result = await deviceService.reverifyDevice(id, request.user!.id);

    if (!result) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'Device is not in SUSPICIOUS state.',
      });
    }

    return reply.send({ message: 'Device re-verified as trusted.' });
  });

  // -------------------------------------------------------------------------
  // GET /policy — Get the current org device policy
  // -------------------------------------------------------------------------

  fastify.get('/policy', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const policy = await policyService.getPolicy(request.user!.orgId);

    if (!policy) {
      return reply.send({ policy: null });
    }

    return reply.send({ policy });
  });

  // -------------------------------------------------------------------------
  // PUT /policy — Create or update the org device policy (OWNER/ADMIN only)
  // -------------------------------------------------------------------------

  fastify.put('/policy', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: updateDevicePolicySchema }),
  }, async (request, reply) => {
    const body = request.body as {
      maxDevices?: number;
      requireBiometric?: boolean;
      geoFenceLat?: number | null;
      geoFenceLng?: number | null;
      geoFenceRadiusKm?: number | null;
      autoRevokeAfterDays?: number | null;
      bridgePolicy?: 'required' | 'optional' | 'disabled';
    };

    const policy = await policyService.upsertPolicy(request.user!.orgId, body);

    return reply.send({ policy });
  });
}
