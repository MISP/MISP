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

  async objectTemplates() {
    return (await this.get('/object_templates/index/all')).map((t) => t.ObjectTemplate);
  }

  // Restore function for the active state of an object template.
  async keepObjectTemplateActive(name) {
    const find = async () => (await this.objectTemplates()).find((t) => t.name === name);
    const { id, active } = await find();
    return async () => {
      if ((await find()).active !== active) await this.post(`/objectTemplates/toggleActive/${id}`);
    };
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

  // Note attached to an event, note or opinion (`objectType` is its model name).
  async addNote(objectUuid, objectType, note) {
    const res = await this.post(`/analystData/add/Note/${objectUuid}/${objectType}`, { note });
    return res.Note || res;
  }

  // Proposal (shadow attribute) on an event of another organisation.
  async proposeAttribute(eventId, { type, value, category = 'Network activity', comment = '' }) {
    const res = await this.post(`/shadow_attributes/add/${eventId}`, {
      ShadowAttribute: { type, value, category, comment, to_ids: 0 },
    });
    return res.ShadowAttribute || res;
  }

  async addCorrelationExclusion(value, comment = '') {
    return this.post('/correlation_exclusions/add', { value, comment });
  }

  async correlationExclusions() {
    const list = await this.get('/correlation_exclusions/index');
    return list.map((x) => x.CorrelationExclusion || x);
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

  async createReport(eventId, name, content = '') {
    const { EventReport } = await this.post(`/eventReports/add/${eventId}`, {
      EventReport: { name, content, distribution: 5 },
    });
    return EventReport;
  }

  // A sharing group with the organisations `orgNames` (by name).
  async createSharingGroup(name, orgNames) {
    const { SharingGroup } = await this.post('/sharing_groups/add', {
      SharingGroup: { name, releasability: 'QA', description: 'QA test data', active: 1 },
    });
    for (const orgName of orgNames) {
      const org = await this.findOrg(orgName);
      await this.post(`/sharing_groups/addOrg/${SharingGroup.id}/${org.id}`);
    }
    return SharingGroup;
  }

  async deleteWarninglistByName(name) {
    const list = await this.findWarninglist(name);
    if (list) await this.post(`/warninglists/delete/${list.id}`);
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

  // Raw request: { status, text } without throwing on an error status.
  async raw(method, url, data) {
    const res = await (await this.ctx()).fetch(url, { method, data });
    return { status: res.status(), text: await res.text() };
  }

  // Throwaway user, so login and password tests leave the QA accounts alone.
  async createUser({ email, password, orgName = 'ADMIN', roleName = 'User' }) {
    const org = await this.findOrg(orgName);
    const roles = (await this.get('/roles/index')).map((r) => r.Role || r);
    const role = roles.find((r) => r.name === roleName);
    if (!role) throw new Error(`No role ${roleName} on the instance`);
    const { User } = await this.post('/admin/users/add', {
      email, password, org_id: org.id, role_id: role.id, change_pw: 0, termsaccepted: 1,
    });
    return User;
  }

  async deleteUserByEmail(email) {
    const users = await this.get('/admin/users/index');
    for (const u of users.map((x) => x.User || x).filter((x) => x.email === email)) {
      await this.post(`/admin/users/delete/${u.id}`);
    }
  }

  // New key for a user; returns the key in clear (only given once).
  async createAuthKey(userId, comment = '') {
    const res = await this.post(`/auth_keys/add/${userId}`, { comment });
    return (res.AuthKey || res).authkey_raw;
  }

  async findUser(email) {
    const users = await this.get('/admin/users/index');
    return users.map((x) => x.User || x).find((x) => x.email.toLowerCase() === email.toLowerCase());
  }

  async deleteAuthKeysByComment(comment) {
    const keys = await this.get('/auth_keys/index');
    for (const k of keys.map((x) => x.AuthKey || x).filter((x) => x.comment === comment)) {
      await this.post(`/auth_keys/delete/${k.id}`);
    }
  }

  async createOrg(name) {
    const res = await this.post('/admin/organisations/add', { name, local: 1 });
    return res.Organisation || res;
  }

  async deleteOrgByName(name) {
    const orgs = await this.get('/organisations/index/scope:all');
    for (const o of orgs.map((x) => x.Organisation).filter((x) => x.name === name)) {
      await this.post(`/admin/organisations/delete/${o.id}`);
    }
  }

  async getSetting(name) {
    return (await this.get(`/servers/getSetting/${name}`)).value;
  }

  // `force` skips the setting's own check (e.g. an empty value).
  async setSetting(name, value, force = false) {
    return this.raw('POST', `/servers/serverSettingsEdit/${name}`, { value: `${value}`, force });
  }

  // Restore function for the current value of a setting.
  async keepSetting(name) {
    const value = await this.getSetting(name);
    return async () => {
      const res = await this.setSetting(name, value ?? '', true);
      if (res.status >= 400) throw new Error(`Could not restore ${name}: ${res.text.slice(0, 200)}`);
    };
  }

  // Deletes the rows of an index whose `field` passes `match` (a string is a prefix).
  async deleteWhere(listUrl, model, field, match, deleteUrl) {
    const test = typeof match === 'string' ? (v) => `${v}`.startsWith(match) : match;
    const list = await this.get(listUrl);
    for (const item of list.map((x) => x[model] || x).filter((x) => test(x[field] ?? ''))) {
      await this.post(`${deleteUrl}/${item.id}`);
    }
  }

  async listOf(listUrl, model) {
    return (await this.get(listUrl)).map((x) => x[model] || x);
  }

  async dispose() {
    await this._ctx?.dispose();
  }
}

// API client authenticated as one of the test roles.
const roleApi = (role) => new MispApi(credentials(role).key);
const adminApi = () => roleApi('siteAdmin');

module.exports = { MispApi, DIST, adminApi, roleApi };
