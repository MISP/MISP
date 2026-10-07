const { request } = require('@playwright/test');
const { MISP_URL, credentials } = require('./env');

// Distribution levels as the MISP API expects them.
const DIST = { org: 0, community: 1, connected: 2, all: 3, sharingGroup: 4 };

class MispApi {
  constructor(key) {
    if (!key) throw new Error('Missing API key in .env');
    this.key = key;
  }

  async ctx() {
    this._ctx ??= await request.newContext({
      baseURL: MISP_URL,
      ignoreHTTPSErrors: true,
      // Never send a browser session: MISP destroys the session a request
      // authenticated by API key arrives with.
      storageState: { cookies: [], origins: [] },
      extraHTTPHeaders: {
        Authorization: this.key,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    });
    return this._ctx;
  }

  async call(method, url, data) {
    const ctx = await this.ctx();
    const res = await ctx.fetch(url, { method, data });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    if (!res.ok()) {
      throw new Error(`${method} ${url} -> HTTP ${res.status()}: ${text.slice(0, 300)}`);
    }
    return body;
  }

  get(url) { return this.call('GET', url); }
  post(url, data = {}) { return this.call('POST', url, data); }

  /**
   * Creates an event. `attributes` items: { type, value, category?, to_ids? };
   * `objects` items: { name, comment?, attributes: [{ object_relation, type, value }] }.
   */
  async createEvent({
    info, distribution = 'org', sharingGroupId, threatLevel = 4, analysis = 0,
    date, attributes = [], objects = [], tags = [], publish = false,
  }) {
    const event = {
      info,
      distribution: DIST[distribution],
      threat_level_id: threatLevel,
      analysis,
      Attribute: attributes.map((a) => ({ to_ids: false, ...a })),
    };
    if (date) event.date = date;
    if (sharingGroupId) event.sharing_group_id = sharingGroupId;
    const { Event } = await this.post('/events/add', { Event: event });
    for (const o of objects) await this.addObject(Event.id, o);
    for (const tag of tags) {
      await this.post('/tags/attachTagToObject', { uuid: Event.uuid, tag });
    }
    if (publish) await this.post(`/events/publish/${Event.id}`);
    return Event;
  }

  async addObject(eventId, { name, comment = '', attributes }) {
    const templateId = await this.objectTemplateId(name);
    const { Object } = await this.post(`/objects/add/${eventId}/${templateId}`, {
      Object: { distribution: 5, comment },
      Attribute: attributes,
    });
    return Object;
  }

  async objectTemplateId(name) {
    this._templates ??= await this.get('/object_templates/index/all');
    const t = this._templates.find((x) => x.ObjectTemplate.name === name);
    if (!t) throw new Error(`No object template ${name}`);
    return t.ObjectTemplate.id;
  }

  async getEvent(id) {
    return (await this.get(`/events/view/${id}`)).Event;
  }

  async findEvents(info) {
    const { response } = await this.post('/events/restSearch', {
      eventinfo: info, metadata: true, returnFormat: 'json',
    });
    return (response || []).map((e) => e.Event).filter((e) => e.info === info);
  }

  async deleteEventsByInfo(info) {
    for (const e of await this.findEvents(info)) {
      await this.post(`/events/delete/${e.id}`);
    }
  }

  async findEventTemplate(name) {
    const list = await this.get('/event_templates/index');
    return list.map((t) => t.EventTemplate).find((t) => t.name === name);
  }

  // Loads the bundled template library if needed and activates `name`.
  // Returns a function that puts the template back in its previous state.
  async activateEventTemplate(name) {
    let template = await this.findEventTemplate(name);
    if (!template) {
      await this.post('/event_templates/update');
      template = await this.findEventTemplate(name);
    }
    if (!template) throw new Error(`No event template ${name}, even in the library`);
    const wasActive = template.active;
    if (!wasActive) await this.post(`/event_templates/edit/${template.id}`, { active: 1 });
    return async () => {
      if (!wasActive) await this.post(`/event_templates/edit/${template.id}`, { active: 0 });
    };
  }

  async deleteCorrelationExclusion(value) {
    const list = await this.get('/correlation_exclusions/index');
    for (const e of list.map((x) => x.CorrelationExclusion || x).filter((x) => x.value === value)) {
      await this.post(`/correlation_exclusions/delete/${e.id}`);
    }
  }

  async findWarninglist(name) {
    const { Warninglists } = await this.post('/warninglists/index', { value: name });
    return Warninglists.map((w) => w.Warninglist).find((w) => w.name === name);
  }

  // Enables a warninglist; returns a function that puts it back as it was.
  async enableWarninglist(name) {
    const list = await this.findWarninglist(name);
    if (!list) throw new Error(`No warninglist ${name}`);
    if (list.enabled) return async () => {};
    await this.post('/warninglists/toggleEnable', { id: list.id, enabled: 1 });
    return async () => this.post('/warninglists/toggleEnable', { id: list.id, enabled: 0 });
  }

  async createTag(name, colour = '#7c3aed') {
    const { Tag } = await this.post('/tags/add', { Tag: { name, colour, exportable: true } });
    return Tag;
  }

  async deleteTag(name) {
    const found = await this.post('/tags/search', { tag: name });
    for (const t of (Array.isArray(found) ? found : []).map((x) => x.Tag || x)) {
      if (t.name === name) await this.post(`/tags/delete/${t.id}`);
    }
  }

  async findTag(name) {
    const found = await this.post('/tags/search', { tag: name });
    return (Array.isArray(found) ? found : []).map((x) => x.Tag || x).find((t) => t.name === name);
  }

  // Makes a hidden tag visible; returns a function that hides it again.
  async showTag(name) {
    const tag = await this.findTag(name);
    if (!tag) throw new Error(`No tag ${name}`);
    if (!tag.hide_tag) return async () => {};
    await this.post(`/tags/edit/${tag.id}`, { Tag: { hide_tag: false } });
    return async () => this.post(`/tags/edit/${tag.id}`, { Tag: { hide_tag: true } });
  }

  async deleteEventsByTag(tag) {
    const { response } = await this.post('/events/restSearch', {
      tags: [tag], metadata: true, returnFormat: 'json',
    });
    for (const { Event } of response || []) await this.post(`/events/delete/${Event.id}`);
  }

  async findTaxonomy(namespace) {
    return (await this.get('/taxonomies/index')).map((t) => t.Taxonomy).find((t) => t.namespace === namespace);
  }

  // Remembers the enabled/required state of a taxonomy; returns a function that restores it.
  async keepTaxonomyState(namespace) {
    const before = await this.findTaxonomy(namespace);
    return async () => {
      const now = await this.findTaxonomy(namespace);
      if (now.enabled !== before.enabled) {
        await this.post(`/taxonomies/${before.enabled ? 'enable' : 'disable'}/${before.id}`);
      }
      if (now.required !== before.required) {
        await this.post(`/taxonomies/toggleRequired/${before.id}`, { Taxonomy: { required: before.required ? 1 : 0 } });
      }
    };
  }

  // Enables a taxonomy; returns a function that puts it back as it was.
  async enableTaxonomy(namespace) {
    const taxonomy = (await this.get('/taxonomies/index'))
      .map((t) => t.Taxonomy).find((t) => t.namespace === namespace);
    if (!taxonomy) throw new Error(`No taxonomy ${namespace}`);
    if (taxonomy.enabled) return async () => {};
    await this.post(`/taxonomies/enable/${taxonomy.id}`);
    return async () => this.post(`/taxonomies/disable/${taxonomy.id}`);
  }

  async deleteTagCollection(name) {
    const list = await this.get('/tag_collections/index');
    for (const c of list.map((x) => x.TagCollection || x).filter((x) => x.name === name)) {
      await this.post(`/tag_collections/delete/${c.id}`);
    }
  }

  async createGalaxy(name, namespace = 'qa') {
    const { Galaxy } = await this.post('/galaxies/add', {
      Galaxy: { name, namespace, description: 'QA test data', distribution: 0 },
    });
    return Galaxy;
  }

  async findGalaxy(name) {
    const { response } = await this.post('/galaxies/index', { value: name }).catch(() => ({}));
    const list = response || await this.get('/galaxies/index');
    return list.map((g) => g.Galaxy || g).find((g) => g.name === name);
  }

  async deleteGalaxyByName(name) {
    const galaxy = await this.findGalaxy(name);
    if (galaxy) await this.post(`/galaxies/delete/${galaxy.id}`);
  }

  async createCluster(galaxyId, value, extra = {}) {
    const { GalaxyCluster } = await this.post(`/galaxy_clusters/add/${galaxyId}`, {
      GalaxyCluster: { value, description: 'QA test data', distribution: 0, authors: [], ...extra },
    });
    return GalaxyCluster;
  }

  async getCluster(id) {
    return (await this.get(`/galaxy_clusters/view/${id}`)).GalaxyCluster;
  }

  // The cluster `value` of the galaxy type `type` (e.g. 'threat-actor', 'APT28').
  async findCluster(type, value) {
    const { response } = await this.post('/galaxy_clusters/restSearch', { value });
    return (response || []).map((c) => c.GalaxyCluster).find((c) => c.type === type && c.value === value);
  }

  async findSharingGroup(name) {
    const { response } = await this.get('/sharing_groups/index');
    return (response || []).find((sg) => sg.SharingGroup.name === name)?.SharingGroup;
  }

  async deleteSharingGroupByName(name) {
    const sg = await this.findSharingGroup(name);
    if (sg) await this.post(`/sharing_groups/delete/${sg.id}`);
  }

  async findOrg(name) {
    const orgs = await this.get('/organisations/index/scope:all');
    const org = orgs.find((o) => o.Organisation.name === name);
    if (!org) throw new Error(`No organisation ${name} on the instance`);
    return org.Organisation;
  }

  async dispose() {
    await this._ctx?.dispose();
  }
}

// API client authenticated as one of the test roles.
const roleApi = (role) => new MispApi(credentials(role).key);
const adminApi = () => roleApi('siteAdmin');

module.exports = { MispApi, DIST, adminApi, roleApi };
