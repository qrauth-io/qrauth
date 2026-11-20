import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import { AuthorizationError, ConflictError, NotFoundError, QRAuthError } from '../errors.js';
import {
  bulkTagResponse,
  folderResponse,
  listFoldersResponse,
  listTagsResponse,
  searchListResponse,
  tagResponse,
} from './fixtures/wire.js';

function respond(body: unknown, status = 200) {
  const fetchMock = vi.fn().mockResolvedValue(
    body === null
      ? new Response(null, { status })
      : new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** The URL, method and parsed JSON body of the first fetch call. */
function sent(fetchMock: ReturnType<typeof respond>) {
  const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return { url, method: init.method, body: init.body ? JSON.parse(init.body as string) : undefined };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const client = () => new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

describe('list() search and filters', () => {
  it('sends q, contentType, comma-joined tagIds and folderId', async () => {
    const fetchMock = respond(searchListResponse);

    const res = await client().list({ q: 'menu', contentType: 'url', tagIds: ['t1', 't2'], folderId: 'unfiled', status: 'ACTIVE' });

    const url = new URL(sent(fetchMock).url);
    expect(url.pathname).toBe('/api/v1/qrcodes');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      status: 'ACTIVE',
      q: 'menu',
      contentType: 'url',
      tagIds: 't1,t2',
      folderId: 'unfiled',
    });
    expect(res).toEqual(searchListResponse);
  });

  it('omits an empty tagIds list and unset filters', async () => {
    const fetchMock = respond(searchListResponse);

    await client().list({ tagIds: [] });

    expect(sent(fetchMock).url).toBe('https://api.test/api/v1/qrcodes');
  });

  it('list items carry their tags and folder', async () => {
    respond(searchListResponse);

    const [item] = (await client().list()).data;

    expect(item.tags).toEqual([{ id: tagResponse.id, name: 'Summer', color: 'teal' }]);
    expect(item.folder).toEqual({ id: folderResponse.id, name: 'Lobby' });
    expect(item.destinationHost).toBe('menu.example.com');
  });

  it('get() returns the same tags and folder shapes as list items', async () => {
    const [item] = searchListResponse.data;
    respond(item);

    const qr = await client().get(item.token);

    expect(qr.tags).toEqual(item.tags);
    expect(qr.folder).toEqual(item.folder);
  });

  it('another organization\'s tag id is a NotFoundError', async () => {
    respond({ statusCode: 404, error: 'Not Found', message: 'Tag "x" not found.' }, 404);

    await expect(client().list({ tagIds: ['x'] })).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe('tags', () => {
  it('listTags() returns the data array', async () => {
    const fetchMock = respond(listTagsResponse);

    expect(await client().listTags()).toEqual([tagResponse]);
    expect(sent(fetchMock)).toMatchObject({ url: 'https://api.test/api/v1/tags', method: 'GET' });
  });

  it('createTag() posts name and colour', async () => {
    const fetchMock = respond(tagResponse, 201);

    const tag = await client().createTag({ name: 'Summer', color: 'teal' });

    expect(sent(fetchMock)).toEqual({ url: 'https://api.test/api/v1/tags', method: 'POST', body: { name: 'Summer', color: 'teal' } });
    expect(tag).toEqual(tagResponse);
  });

  it('updateTag() patches the encoded id; deleteTag() resolves on 204', async () => {
    const patchMock = respond(tagResponse);
    await client().updateTag('a/b', { color: 'red' });
    expect(sent(patchMock)).toEqual({ url: 'https://api.test/api/v1/tags/a%2Fb', method: 'PATCH', body: { color: 'red' } });

    const deleteMock = respond(null, 204);
    await expect(client().deleteTag('t1')).resolves.toBeUndefined();
    expect(sent(deleteMock)).toMatchObject({ url: 'https://api.test/api/v1/tags/t1', method: 'DELETE' });
  });

  it.each([['name-taken'], ['limit-reached']])('a 409 %s is a ConflictError with that reason', async (reason) => {
    respond({ statusCode: 409, error: 'Conflict', code: reason, message: 'Conflict message' }, 409);

    const err = await client().createTag({ name: 'Summer' }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ConflictError);
    expect(err).toBeInstanceOf(QRAuthError);
    expect(err).toMatchObject({ statusCode: 409, code: 'CONFLICT', reason, message: 'Conflict message' });
  });

  it('a VIEWER key is an AuthorizationError', async () => {
    respond({ statusCode: 403, error: 'Forbidden', message: 'Insufficient permissions' }, 403);

    await expect(client().createTag({ name: 'Summer' })).rejects.toBeInstanceOf(AuthorizationError);
  });
});

describe('folders', () => {
  it('listFolders() returns the folders and the unfiled count', async () => {
    respond(listFoldersResponse);

    const res = await client().listFolders();

    expect(res.data).toEqual([folderResponse]);
    expect(res.unfiledCount).toBe(4);
  });

  it('createFolder() and renameFolder() send the name', async () => {
    const createMock = respond(folderResponse, 201);
    await client().createFolder('Lobby');
    expect(sent(createMock)).toEqual({ url: 'https://api.test/api/v1/folders', method: 'POST', body: { name: 'Lobby' } });

    const renameMock = respond(folderResponse);
    await client().renameFolder('f1', 'Lobby');
    expect(sent(renameMock)).toEqual({ url: 'https://api.test/api/v1/folders/f1', method: 'PATCH', body: { name: 'Lobby' } });
  });

  it('deleteFolder() resolves on 204', async () => {
    const fetchMock = respond(null, 204);

    await expect(client().deleteFolder('f1')).resolves.toBeUndefined();
    expect(sent(fetchMock)).toMatchObject({ url: 'https://api.test/api/v1/folders/f1', method: 'DELETE' });
  });
});

describe('bulk tag and move', () => {
  it('bulkTag() sends tokens with add and remove', async () => {
    const fetchMock = respond(bulkTagResponse);

    const res = await client().bulkTag(['RKcPf9kv', 'zzzzzzzz'], { add: ['t1'], remove: ['t2'] });

    expect(sent(fetchMock)).toEqual({
      url: 'https://api.test/api/v1/qrcodes/bulk-tag',
      method: 'POST',
      body: { tokens: ['RKcPf9kv', 'zzzzzzzz'], add: ['t1'], remove: ['t2'] },
    });
    expect(res).toEqual(bulkTagResponse);
  });

  it('bulkMove() sends folderId, including null to unfile', async () => {
    const fetchMock = respond(bulkTagResponse);

    await client().bulkMove(['RKcPf9kv'], null);

    expect(sent(fetchMock).body).toEqual({ tokens: ['RKcPf9kv'], folderId: null });
  });

  it('needs an API key', async () => {
    const appOnly = new QRAuth({ clientId: 'c', clientSecret: 's', baseUrl: 'https://api.test' });
    await expect(appOnly.bulkMove(['RKcPf9kv'], 'f1')).rejects.toThrow('apiKey is required');
  });
});
