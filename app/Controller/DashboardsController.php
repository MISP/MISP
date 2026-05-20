<?php
App::uses('AppController', 'Controller');

/**
 * Dashboard controller (v2). Mounted at /dashboards/* via CakePHP's
 * default routing.
 *
 * @property Dashboard $Dashboard
 */
class DashboardsController extends AppController
{
    public $components = array('Session', 'RequestHandler');
    public $uses = array('Dashboard', 'User');

    public function beforeFilter()
    {
        parent::beforeFilter();
        // POSTs carry widget data in their body — same CSRF posture
        // as the v1 dashboards endpoints.
        $bodyPostActions = array('renderWidget', 'renderWrapper', 'updateSettings', 'updateWidgetSettings');
        foreach ($bodyPostActions as $a) {
            $this->Security->unlockedActions[] = $a;
        }
        if (in_array($this->request->action, $bodyPostActions, true)) {
            $this->Security->doNotGenerateToken = true;
        }
    }

    public function index()
    {
        App::uses('LayoutFixup', 'Lib/Dashboard/Tools');
        App::uses('WidgetSchema', 'Lib/Dashboard/Tools');
        // Layout priority chain:
        //   1. If the user has a UserSetting:dashboard row (even with
        //      an empty array as the value), use that — a user who
        //      explicitly cleared their dashboard should NOT have a
        //      default template silently re-imposed on next visit.
        //   2. Else look up the org/role/permission-restricted default
        //      template via Dashboard::getDashboardTemplate, json_decode
        //      its `value` field, and use that.
        //   3. Else hand the view an empty array — the view renders
        //      the empty-state element ("No widgets yet").
        // On-read fix-ups (DD-05) normalise per-widget shape regardless
        // of source: width/height → w/h, instance_id minted if missing.
        // updateSettings writes go through the same path so persisted
        // shape is canonical. Top-level stays bare-array (DD-05).
        $user = $this->Auth->user();
        // getValueForUser distinguishes "row exists with empty value"
        // (returns []) from "no row at all" (returns null). getSetting
        // collapses both to [] which would silently re-impose the
        // default template on a user who'd cleared their dashboard.
        $saved = $this->User->UserSetting->getValueForUser($user['id'], 'dashboard');
        if (is_array($saved)) {
            $widgets = LayoutFixup::applyReadFixups($saved);
        } else {
            $widgets = array();
            $template = $this->Dashboard->getDashboardTemplate($user);
            if (!empty($template['Dashboard']['value'])) {
                $decoded = json_decode($template['Dashboard']['value'], true);
                if (is_array($decoded)) {
                    $widgets = LayoutFixup::applyReadFixups($decoded);
                }
            }
        }

        // REST clients get the layout payload as JSON via the
        // RestResponse component. Web UI falls through to
        // View/Dashboards/index.ctp under Layouts/dashboard.ctp.
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($widgets, $this->response->type());
        }

        // Enrich each widget with its declared $schema (PRD §5.7) and
        // $placeholder (DD-06 bottom-tier seeding) so the wrapper can
        // emit data-widget-schema + data-widget-placeholder and the
        // client-side configure form renders the typed-fields tier from
        // the contract while seeding the bottom-tier kv list from the
        // widget's example payload. Unknown widget classes resolve to an
        // empty schema and an empty placeholder — the configure form
        // then collapses to a single-empty-row kv tier (DD-06 custom-
        // widgets path). $placeholder ships raw (not server-parsed) so
        // the client owns the JSON.parse-and-fallback path — some legacy
        // placeholders carry trailing commas and similar malformations.
        foreach ($widgets as &$w) {
            $w['schema'] = [];
            $w['placeholder'] = '';
            if (!empty($w['widget']) && is_string($w['widget'])) {
                $instance = $this->Dashboard->loadWidget($user, $w['widget'], true);
                if ($instance !== false) {
                    $w['schema'] = WidgetSchema::getSchema($instance);
                    if (isset($instance->placeholder) && is_string($instance->placeholder)) {
                        $w['placeholder'] = $instance->placeholder;
                    }
                }
            }
        }
        unset($w);

        $this->layout = 'dashboard';
        $this->set('title_for_layout', __('Dashboard'));
        $this->set('widgets', $widgets);
    }

    /**
     * Persist the user's dashboard layout. Mirrors v1's
     * `DashboardsController::updateSettings` contract so REST clients
     * written against v1 keep working: `POST {Dashboard: {value:
     * [...widgets]}}`. Top-level shape stays a bare array; per-widget
     * fix-ups apply on write so the saved shape is canonical.
     */
    public function updateSettings()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        if (!isset($this->request->data['Dashboard']['value'])) {
            throw new BadRequestException(__('No setting data found.'));
        }
        $widgets = $this->request->data['Dashboard']['value'];
        if (is_string($widgets)) {
            $decoded = json_decode($widgets, true);
            $widgets = is_array($decoded) ? $decoded : array();
        }
        App::uses('LayoutFixup', 'Lib/Dashboard/Tools');
        $widgets = LayoutFixup::applyReadFixups($widgets);

        // UserSetting's validate_json hook expects the value as a JSON
        // string (matches v1's wire form: Dashboard[value]=<encoded>);
        // passing a nested array trips a json_validate type check on
        // PHP 8.3. Encode here so the model's beforeSave passes it
        // through unmodified.
        $data = array(
            'UserSetting' => array(
                'setting' => 'dashboard',
                'value'   => json_encode($widgets, JSON_UNESCAPED_SLASHES),
            ),
        );
        $result = $this->User->UserSetting->setSetting(
            $this->Auth->user(),
            $data
        );
        if ($result) {
            return $this->RestResponse->saveSuccessResponse(
                'Dashboard',
                'updateSettings',
                false,
                false,
                __('Settings updated.')
            );
        }
        return $this->RestResponse->saveFailResponse(
            'Dashboard',
            'updateSettings',
            false,
            $this->User->UserSetting->validationErrors,
            $this->response->type()
        );
    }

    /**
     * Per-widget config patch (DD-05): persist a config change for one
     * or more widgets without touching the rest of the saved layout.
     * The configure-form Save and the toolbar's bulk-edit both POST
     * here so neither path commits staged layout edits sitting in the
     * client during edit mode.
     *
     * Wire shape:
     *   POST data[patches]=<JSON array of {instance_id, config}>
     *
     * Single-widget callers (configure form) send a one-entry array;
     * bulk callers (toolbar) send N entries — the server applies all
     * patches in a single setSetting write so partial failures don't
     * leave the blob in a mixed state.
     *
     * 404 on no saved blob (the client falls back to a full
     * `updateSettings` so first-save users aren't stuck) or on an
     * unknown instance_id (likely concurrent removal in another tab).
     */
    public function updateWidgetSettings()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        $rawPatches = isset($this->request->data['patches'])
            ? $this->request->data['patches']
            : null;
        if ($rawPatches === null) {
            throw new BadRequestException(__('No patches provided.'));
        }
        $patches = is_string($rawPatches)
            ? json_decode($rawPatches, true)
            : $rawPatches;
        if (!is_array($patches) || empty($patches)) {
            throw new BadRequestException(__('Malformed or empty patches.'));
        }

        // Normalise + validate each patch entry up front so a malformed
        // entry can't half-apply.
        $normalised = array();
        foreach ($patches as $patch) {
            if (!is_array($patch)) {
                throw new BadRequestException(__('Patch entry must be an object.'));
            }
            if (empty($patch['instance_id']) || !is_string($patch['instance_id'])) {
                throw new BadRequestException(__('Patch entry missing instance_id.'));
            }
            if (!array_key_exists('config', $patch)) {
                throw new BadRequestException(__('Patch entry missing config.'));
            }
            $cfg = $patch['config'];
            if (is_string($cfg)) {
                $cfg = json_decode($cfg, true);
            }
            if (!is_array($cfg)) {
                $cfg = array();
            }
            $normalised[] = array(
                'instance_id' => $patch['instance_id'],
                'config'      => $cfg,
            );
        }

        $user = $this->Auth->user();
        $saved = $this->User->UserSetting->getValueForUser($user['id'], 'dashboard');
        if (!is_array($saved)) {
            throw new NotFoundException(__('No saved dashboard layout.'));
        }
        App::uses('LayoutFixup', 'Lib/Dashboard/Tools');
        App::uses('CanonicalTypeAdapter', 'Lib/Dashboard/Tools');
        $widgets = LayoutFixup::applyReadFixups($saved);

        // Index widgets by instance_id once; patches touching the same
        // instance more than once apply in order (last write wins).
        $index = array();
        foreach ($widgets as $i => $w) {
            if (!empty($w['instance_id'])) {
                $index[$w['instance_id']] = $i;
            }
        }
        // PRD §5.5 — validate canonical-typed slots before applying any
        // patch. Catches malformed shapes (e.g. tag_filter as a scalar,
        // threat_level as a non-numeric string) loudly at save time
        // rather than letting them silently coerce to empty filters at
        // render time. Validators accept both canonical and legacy
        // shapes; a layout-drag re-POST of an un-edited legacy config
        // passes through unchanged.
        $validationErrors = array();
        foreach ($normalised as $p) {
            if (!isset($index[$p['instance_id']])) {
                throw new NotFoundException(__('Widget instance not found in saved layout.'));
            }
            $className = $widgets[$index[$p['instance_id']]]['widget'];
            try {
                $widget = $this->Dashboard->loadWidget($user, $className);
            } catch (Exception $e) {
                // Widget class missing or ACL-blocked — skip validation
                // for this patch and let the save proceed. The render-
                // time path will surface the underlying error.
                $widget = null;
            }
            if ($widget !== null) {
                $errs = CanonicalTypeAdapter::validate($widget, $p['config']);
                if ($errs !== null) {
                    $validationErrors[$p['instance_id']] = $errs;
                }
            }
        }
        if (!empty($validationErrors)) {
            throw new BadRequestException(__(
                'Canonical-type validation failed: %s',
                json_encode($validationErrors, JSON_UNESCAPED_SLASHES)
            ));
        }
        foreach ($normalised as $p) {
            $widgets[$index[$p['instance_id']]]['config'] = $p['config'];
        }

        $data = array(
            'UserSetting' => array(
                'setting' => 'dashboard',
                'value'   => json_encode($widgets, JSON_UNESCAPED_SLASHES),
            ),
        );
        $result = $this->User->UserSetting->setSetting($user, $data);
        if ($result) {
            return $this->RestResponse->saveSuccessResponse(
                'Dashboard',
                'updateWidgetSettings',
                false,
                false,
                __('Widget settings updated.')
            );
        }
        return $this->RestResponse->saveFailResponse(
            'Dashboard',
            'updateWidgetSettings',
            false,
            $this->User->UserSetting->validationErrors,
            $this->response->type()
        );
    }

    public function renderWidget($instance_id = null)
    {
        App::uses('CanonicalTypeAdapter', 'Lib/Dashboard/Tools');
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        $widgetName = isset($this->request->data['widget']) ? $this->request->data['widget'] : null;
        $rawConfig  = isset($this->request->data['config']) ? $this->request->data['config'] : '[]';
        $config = is_string($rawConfig)
            ? (json_decode($rawConfig, true) ?: array())
            : (array)$rawConfig;
        if (empty($widgetName) || !preg_match('/^[A-Za-z0-9_]+Widget$/', $widgetName)) {
            throw new BadRequestException(__('Missing or malformed widget name.'));
        }

        $widget = $this->Dashboard->loadWidget($this->Auth->user(), $widgetName);
        // PRD §5.5 keystone — translate canonical wire shapes (ISO 8601
        // durations, etc.) into the legacy shapes each widget's handler()
        // parses, driven off $widget->$schema. Also injects schema-
        // declared defaults for missing keys. Legacy values (existing
        // saved configs) and keys without a schema entry pass through
        // unchanged.
        $config = CanonicalTypeAdapter::translate($widget, $config);
        $data = $widget->handler($this->Auth->user(), $config);
        $renderer = method_exists($widget, 'getRenderer')
            ? $widget->getRenderer($config)
            : $widget->render;

        // Mirrors the v1 dashboards renderWidget pattern: explicit
        // exportjson / exportcsv named params force REST output even
        // from a browser session; otherwise _isRest() drives the choice.
        $named = isset($this->request->params['named']) ? $this->request->params['named'] : array();
        if (!empty($named['exportjson']) || ($this->_isRest() && empty($named['exportcsv']))) {
            return $this->RestResponse->viewData(array(
                'instance_id' => $instance_id,
                'widget'      => $widgetName,
                'config'      => $config,
                'renderer'    => $renderer,
                'data'        => $data,
            ), $this->response->type());
        }
        if (!empty($named['exportcsv'])) {
            return $this->RestResponse->viewData(
                $this->_dataToCsv($data),
                'text/csv',
                false,
                true
            );
        }

        // Web UI: render the widget body HTML via the renderer dispatcher.
        $this->layout = false;
        $this->set('widget', $widget);
        $this->set('data', $data);
        $this->set('instance_id', $instance_id);
        $this->set('renderer', $renderer);
        $this->set('config', $config);
        $this->render('render_widget');
    }

    /**
     * Flatten a widget's `handler()` return into a CSV string.
     * Mirrors the v1 dashboards renderWidget exportcsv branch closely
     * enough that REST clients written against v1 keep working.
     */
    private function _dataToCsv($data)
    {
        $toConvert = !empty($data) ? (!empty($data['data']) ? $data['data'] : $data) : array();
        if (empty($toConvert)) {
            return '';
        }
        $firstKey = key($toConvert);
        if (is_string($firstKey)) {
            $rows = array();
            foreach ($toConvert as $k => $v) {
                $rows[] = sprintf('%s,%s', $k, json_encode($v));
            }
            return implode(PHP_EOL, $rows) . PHP_EOL;
        }
        $headerKeys = array_keys(Hash::flatten($toConvert[0]));
        $header = implode(',', array_map(function ($s) { return sprintf('"%s"', $s); }, array_map('strval', $headerKeys)));
        $rows = array_map(function ($row) {
            $flat = array_values(Hash::flatten($row));
            $strs = array_map('strval', $flat);
            return implode(',', array_map(function ($s) { return sprintf('"%s"', $s); }, $strs));
        }, $toConvert);
        return $header . PHP_EOL . implode(PHP_EOL, array_values($rows)) . PHP_EOL;
    }

    /**
     * v2 widget metadata endpoint (PRD §5.8). Lists every widget the
     * calling user is eligible for (per each widget's optional
     * checkPermissions hook), with the v2-additional metadata that
     * the Add Widget gallery needs: $schema (typed-fields contract,
     * PRD §5.7), $category (gallery grouping bucket, status / events
     * / tags / orgs / system / custom), and $thumbnail (relative URL
     * to a static preview image, optional).
     *
     * Wire shape is JSON-only — the gallery is XHR-driven and the
     * dashboard's HTML view path has no template for this endpoint.
     * Returns a flat list ordered by class name (the existing
     * `ksort` in `Dashboard::loadAllWidgets`); the client groups by
     * category at render time.
     *
     * The legacy `Dashboard::loadAllWidgets` enumeration is kept
     * untouched (additive-only posture); v2 keys are enriched here
     * by re-loading each widget via `loadWidget` so we have an
     * instance to read the new optional properties off. The
     * double-instantiation cost (~38 widgets) is acceptable for an
     * on-demand gallery open; if it ever surfaces as a hot path the
     * natural cleanup is to fold the enrichment into
     * `Dashboard::__extractMeta` directly.
     */
    public function widgets()
    {
        App::uses('WidgetSchema', 'Lib/Dashboard/Tools');
        $user = $this->Auth->user();
        $widgets = $this->Dashboard->loadAllWidgets($user);
        $out = [];
        foreach ($widgets as $className => $meta) {
            $instance = $this->Dashboard->loadWidget($user, $className, true);
            if ($instance === false) {
                // Race: checkPermissions flipped between the
                // enumeration and the re-load. Skip silently.
                continue;
            }
            $meta['schema'] = WidgetSchema::getSchema($instance);
            $meta['category'] = isset($instance->category)
                && is_string($instance->category)
                ? $instance->category
                : '';
            $meta['thumbnail'] = isset($instance->thumbnail)
                && is_string($instance->thumbnail)
                ? $instance->thumbnail
                : '';
            $out[] = $meta;
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * List sharing groups visible to the current user, in a
     * lightweight `[{id, name}]` shape suitable for the
     * sharing_group_filter canonical picker.
     *
     * The canonical-typed sharing_group_filter slot's JS picker
     * needs a list of options to render. Unlike the int-enum
     * canonicals (distribution / threat_level / analysis) whose
     * valid range is a fixed global enum, sharing groups are
     * user-specific — admin sees every SG, regular users see
     * only the SGs they're members of (or whose org is a member).
     * Embedding a static enum on the client side is impossible.
     *
     * Why a dedicated dashboard endpoint vs.
     * `/sharing_groups/index.json`:
     *   The standard SG index returns the full
     *   {SharingGroup, Organisation, SharingGroupOrg, SharingGroup-
     *   Server, editable, deletable} blob — ~1KB per SG, designed
     *   for the SG browse page. A picker for 50 SGs would download
     *   ~50KB of mostly-irrelevant data. This endpoint trims to
     *   {id, name} per SG (typically <50 bytes), suitable for the
     *   minimal picker UX. Same ACL semantics as the canonical SG
     *   index — `SharingGroup::fetchAllAuthorised` with `scope=name`
     *   delegates the visibility check to the existing model layer.
     *
     * Sorted by name ASC (the `fetchAllAuthorised` 'name' scope
     * returns `[id => name, ...]`; we transform to a list of
     * `{id: int, name: string}` records to make the JS-side
     * consumption an array iteration rather than a Map walk).
     */
    public function listSharingGroups()
    {
        $this->loadModel('SharingGroup');
        $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name');
        $out = [];
        foreach ($sgs as $id => $name) {
            $out[] = [
                'id'   => (int)$id,
                'name' => (string)$name,
            ];
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * List galaxy types for the galaxy_cluster_filter canonical
     * picker's scope dropdown. Returns one entry per enabled galaxy:
     *
     *   [{ type: string,         // galaxies.type (e.g.
     *      name: string,         // galaxies.name
     *      description: string,  // optional
     *      cluster_count: int }, // # of non-deleted clusters
     *    ...]
     *
     * Sorted by cluster_count DESC so high-volume galaxies (mitre-
     * attack-pattern, threat-actor, sigma-rules) surface first in the
     * picker.
     *
     * Read-only public endpoint; same '*' ACL policy as the other
     * dashboard read endpoints. Galaxies are non-sensitive metadata
     * (the catalogue is shared across the public MISP-galaxy repo)
     * — no per-user ACL on the type list. Per-cluster visibility is
     * gated by event ACL on the consumer's query path.
     */
    public function listGalaxyTypes()
    {
        $this->loadModel('Galaxy');
        // One row per galaxy.type via the join + GROUP BY on type.
        // Cake's `find('all')` with joins + group is the standard
        // tool here; the result is post-processed below into the
        // picker's flat shape.
        $rows = $this->Galaxy->find('all', [
            'recursive' => -1,
            'fields' => [
                'Galaxy.type',
                'Galaxy.name',
                'Galaxy.description',
                'COUNT(DISTINCT GalaxyCluster.id) AS cluster_count',
            ],
            'joins' => [[
                'table' => 'galaxy_clusters',
                'alias' => 'GalaxyCluster',
                'type'  => 'LEFT',
                'conditions' => [
                    'GalaxyCluster.galaxy_id = Galaxy.id',
                    'GalaxyCluster.deleted = 0',
                ],
            ]],
            'conditions' => ['Galaxy.enabled' => 1],
            'group' => ['Galaxy.type', 'Galaxy.name', 'Galaxy.description'],
            'order' => ['cluster_count DESC', 'Galaxy.name ASC'],
        ]);
        $out = [];
        foreach ($rows as $row) {
            $out[] = [
                'type'          => (string)$row['Galaxy']['type'],
                'name'          => (string)$row['Galaxy']['name'],
                'description'   => (string)$row['Galaxy']['description'],
                'cluster_count' => (int)$row[0]['cluster_count'],
            ];
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * Typeahead-style search for galaxy clusters, scoped by galaxy
     * type. Returns up to 50 matching clusters per query, ordered
     * alphabetically by value.
     *
     * Query parameters:
     *   - galaxy_type (required): galaxies.type value
     *     (e.g. 'mitre-attack-pattern')
     *   - q          (optional):  case-insensitive substring match
     *     on the cluster's value. Empty / unset = return the first
     *     50 clusters of the type, unfiltered.
     *
     * Response:
     *   [{ tag_name: string, value: string, uuid: string }, ...]
     *
     * Why typeahead vs. exhaustive list: the test instance has
     * 55,036 clusters across 121 galaxy types. Returning all
     * clusters for a single popular type (e.g. mitre-attack-pattern
     * = 1,296 clusters) is still ~150KB of JSON; for sigma-rules
     * (6,961 clusters) it's ~800KB. Substring search caps the
     * payload at the 50-result limit (~5KB typical) and matches the
     * UX pattern users expect from a search-as-you-type input.
     *
     * Read-only public endpoint; same '*' ACL policy as the other
     * dashboard read endpoints.
     */
    public function searchGalaxyClusters()
    {
        $named = isset($this->request->params['named']) ? $this->request->params['named'] : [];
        $query = isset($this->request->query) ? $this->request->query : [];
        $galaxyType = isset($query['galaxy_type']) ? (string)$query['galaxy_type'] : (isset($named['galaxy_type']) ? (string)$named['galaxy_type'] : '');
        $q          = isset($query['q'])          ? (string)$query['q']          : (isset($named['q'])          ? (string)$named['q']          : '');
        if ($galaxyType === '' || !preg_match('/^[A-Za-z0-9_\-]+$/', $galaxyType)) {
            throw new BadRequestException(__('Missing or malformed `galaxy_type` parameter.'));
        }
        $this->loadModel('GalaxyCluster');
        $conditions = [
            'GalaxyCluster.type'    => $galaxyType,
            'GalaxyCluster.deleted' => 0,
        ];
        if ($q !== '') {
            // LIKE with %wrapped% substring match. CakePHP escapes
            // the right-hand value, but `%` and `_` are LIKE wildcards
            // — strip them from user input so the search behaves as
            // a plain substring lookup, not a pattern match.
            $cleanQ = str_replace(['%', '_'], '', $q);
            $conditions['GalaxyCluster.value LIKE'] = '%' . $cleanQ . '%';
        }
        $rows = $this->GalaxyCluster->find('all', [
            'recursive' => -1,
            'fields' => ['GalaxyCluster.tag_name', 'GalaxyCluster.value', 'GalaxyCluster.uuid'],
            'conditions' => $conditions,
            'order' => 'GalaxyCluster.value ASC',
            'limit' => 50,
        ]);
        $out = [];
        foreach ($rows as $row) {
            $out[] = [
                'tag_name' => (string)$row['GalaxyCluster']['tag_name'],
                'value'    => (string)$row['GalaxyCluster']['value'],
                'uuid'     => (string)$row['GalaxyCluster']['uuid'],
            ];
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * Render the widget wrapper element (PRD §8.3) for a new tile
     * just placed by the Add Widget flow. The wrapper carries every
     * §8.5 hook attribute (data-misp-widget, data-widget-*, data-
     * position-*, data-drag-handle, data-misp-widget-content, data-
     * misp-widget-action, data-resize-handle) and resolves through
     * Cake's themed view path, so an Overmind dashboard gets the
     * Overmind-shaped card and a default dashboard gets the default
     * <article>. The widget body stays a "Loading…" placeholder
     * until the client kicks off the usual renderWidget POST.
     *
     * Wire contract:
     *   POST /dashboards/renderWrapper/<instance_id>
     *     widget   class name (validated, regex-gated)
     *     config   JSON-encoded user config (post-form-save)
     *     w, h     grid footprint (cell count); x, y placement
     *
     * ACL posture (per user direction during the placement design):
     *   `loadWidget` enforces `checkPermissions($user)` and throws
     *   `NotFoundException` on failure with the same error shape as
     *   an unknown widget class, so the endpoint cannot be probed
     *   for the existence of admin-only widgets. The gate is
     *   bit-for-bit identical to what `renderWidget` enforces —
     *   add and render paths share the same permission check.
     */
    public function renderWrapper($instance_id = null)
    {
        App::uses('WidgetSchema', 'Lib/Dashboard/Tools');
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        $widgetName = isset($this->request->data['widget']) ? $this->request->data['widget'] : null;
        if (empty($widgetName) || !preg_match('/^[A-Za-z0-9_]+Widget$/', $widgetName)) {
            throw new BadRequestException(__('Missing or malformed widget name.'));
        }
        if (empty($instance_id) || !preg_match('/^w_[A-Za-z0-9_]+$/', $instance_id)) {
            throw new BadRequestException(__('Missing or malformed instance id.'));
        }
        // Same gate as renderWidget — checkPermissions is the
        // authoritative ACL hook; a 404 here is indistinguishable
        // from an unknown widget class, so this endpoint cannot leak
        // the existence of admin-only widgets to a non-admin probe.
        $user = $this->Auth->user();
        $widget = $this->Dashboard->loadWidget($user, $widgetName);

        $rawConfig = isset($this->request->data['config']) ? $this->request->data['config'] : '{}';
        $config = is_string($rawConfig)
            ? (json_decode($rawConfig, true) ?: array())
            : (array)$rawConfig;
        if (!is_array($config)) {
            $config = array();
        }
        // Position falls back to the widget's declared default size if
        // the client didn't send one (defensive — placement always
        // sends, but mis-wired callers shouldn't crash the wrapper).
        $declaredW = isset($widget->width)  && is_numeric($widget->width)  ? (int)$widget->width  : 4;
        $declaredH = isset($widget->height) && is_numeric($widget->height) ? (int)$widget->height : 3;
        $w = isset($this->request->data['w']) ? (int)$this->request->data['w'] : $declaredW;
        $h = isset($this->request->data['h']) ? (int)$this->request->data['h'] : $declaredH;
        $x = isset($this->request->data['x']) ? (int)$this->request->data['x'] : 0;
        $y = isset($this->request->data['y']) ? (int)$this->request->data['y'] : 0;

        // Enrich with $schema + $placeholder so the wrapper emits the
        // attributes the configure form reads on the next Edit cycle
        // (mirrors the index() enrichment loop, kept inline rather
        // than factored so the index() path stays additive-only).
        $schema = WidgetSchema::getSchema($widget);
        $placeholder = isset($widget->placeholder) && is_string($widget->placeholder)
            ? $widget->placeholder
            : '';

        $widgetData = array(
            'widget'      => $widgetName,
            'instance_id' => $instance_id,
            'config'      => $config,
            'schema'      => $schema,
            'placeholder' => $placeholder,
            'alias'       => null,
            'position'    => array('x' => $x, 'y' => $y, 'w' => $w, 'h' => $h),
        );

        // Cake's themed view resolver picks Themed/<Theme>/Elements/
        // dashboard/widget/wrapper.ctp when a theme is active, falls
        // back to the default Elements/dashboard/widget/wrapper.ctp
        // otherwise. AppController::beforeFilter sets $this->theme
        // off UserSetting:ui_theme for non-REST requests; our XHR is
        // not REST (sends Accept: text/html, no auth-key) so the
        // active theme propagates here without extra wiring. The
        // render_wrapper.ctp view file just dispatches to the
        // themed-resolved element — mirrors render_widget.ctp's
        // structure.
        $this->layout = false;
        $this->set('widget', $widgetData);
        $this->render('render_wrapper');
    }

    /* ============================================================
     * Phase 1 v1 carryover (per audit Done note in
     * dashboard-progress.md). The five template / import / export
     * actions live here verbatim during Phase 1 so the dashboard
     * header's "⋯ More" dropdown (DD-08) keeps its URLs working.
     * Phase 4 reimplements each v2-native; until then, no edits
     * other than what the rename pass mechanically rewrites.
     * ============================================================ */

    public function import()
    {
        if ($this->request->is('post')) {
            if (!empty($this->request->data['Dashboard'])) {
                $this->request->data = json_decode($this->request->data['Dashboard']['value'], true);
            }
            if (!empty($this->request->data['UserSetting'])) {
                $this->request->data = $this->request->data['UserSetting']['value'];
            }
            $result = $this->Dashboard->import($this->Auth->user(), $this->request->data);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Dashboard', 'import', false, false, __('Settings updated.'));
                }
                return $this->RestResponse->saveFailResponse('Dashboard', 'import', false, __('Settings could not be updated.'), $this->response->type());
            } else {
                if ($result) {
                    $this->Flash->success(__('Settings updated.'));
                } else {
                    $this->Flash->error(__('Settings could not be updated.'));
                }
                $this->redirect($this->baseurl . '/dashboards');
            }
        }
        $this->layout = false;
    }

    public function export()
    {
        $data = $this->Dashboard->export($this->Auth->user());
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('data', $data);
            $this->layout = false;
        }
    }

    public function saveTemplate($update = false)
    {
        if (!empty($update)) {
            $conditions = array('Dashboard.id' => $update);
            if (Validation::uuid($update)) {
                $conditions = array('Dashboard.uuid' => $update);
            }
            $existingDashboard = $this->Dashboard->find('first', array(
                'recursive' => -1,
                'conditions' => $conditions
            ));
            if (
                empty($existingDashboard) ||
                (!$this->_isSiteAdmin() && $existingDashboard['Dashboard']['user_id'] != $this->Auth->user('id'))
            ) {
                throw new NotFoundException(__('Invalid dashboard template.'));
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (isset($this->request->data['Dashboard'])) {
                $this->request->data = $this->request->data['Dashboard'];
            }
            $data = $this->request->data;
            if (empty($update)) { // save the template stored in user setting and make it persistent
                $data['value'] = $this->User->UserSetting->getSetting($this->Auth->user('id'), 'dashboard');
            }
            $result = $this->Dashboard->saveDashboardTemplate($this->Auth->user(), $data, $update);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Dashboard', 'saveDashboardTemplate', false, false, __('Dashboard template updated.'));
                }
                return $this->RestResponse->saveFailResponse('Dashboard', 'import', false, __('Dashboard template could not be updated.'), $this->response->type());
            } else {
                if ($result) {
                    $this->Flash->success(__('Dashboard template updated.'));
                } else {
                    $this->Flash->error(__('Dashboard template could not be updated.'));
                }
                $this->redirect($this->baseurl . '/dashboards/listTemplates');
            }
        } else {
            $this->layout = false;
        }
        $permFlags = array(0 => __('Unrestricted'));
        foreach ($this->User->Role->permFlags as $perm_flag => $perm_data) {
            $permFlags[$perm_flag] = $perm_data['text'];
        }
        $options = array(
            'org_id' => (
                array(
                    0 => __('Unrestricted')
                ) + // avoid re-indexing
                $this->User->Organisation->find('list', array(
                    'fields' => array(
                        'Organisation.id', 'Organisation.name'
                    ),
                    'conditions' => array('Organisation.local' => 1)
                ))
            ),
            'role_id' => (
                array(
                    0 => __('Unrestricted')
                ) + // avoid re-indexing
                $this->User->Role->find('list', array(
                    'fields' => array(
                        'Role.id', 'Role.name'
                    )
                ))
            ),
            'role_perms' => $permFlags
        );
        if (!empty($update)) {
            $this->request->data = $existingDashboard;
        }
        $this->set('options', $options);
    }

    public function listTemplates()
    {
        $conditions = [];
        $accessible_widgets = array_keys($this->Dashboard->loadAllWidgets($this->Auth->user()));

        if (!$this->_isSiteAdmin()) {
            $permission_flags = [];
            foreach ($this->Auth->user('Role') as $perm => $value) {
                if (strpos($perm, 'perm_') !== false && !empty($value)) {
                    $permission_flags[] = $perm;
                }
            }
            $conditions['AND'] = [
                [
                    'OR' => [
                        'Dashboard.user_id' => $this->Auth->user('id'),
                        'AND' => [
                            'Dashboard.selectable' => 1,
                            ['OR' => [
                                ['Dashboard.restrict_to_org_id' => $this->Auth->user('org_id')],
                                ['Dashboard.restrict_to_org_id' => 0]
                            ]],
                            ['OR' => [
                                ['Dashboard.restrict_to_role_id' => $this->Auth->user('role_id')],
                                ['Dashboard.restrict_to_role_id' => 0]
                            ]],
                            ['OR' => [
                                ['Dashboard.restrict_to_permission_flag' => $permission_flags],
                                ['Dashboard.restrict_to_permission_flag' => 0]
                            ]]
                        ]
                    ]
                ]
            ];
        }

        $currentUserId = $this->Auth->user('id');
        $params = [
            'filters' => ['name', 'description', 'uuid', 'value'],
            'quickFilters' => ['name', 'description', 'uuid'],
            'quickFilterParameter' => 'value',
            'conditions' => $conditions,
            'contain' => ['User.id', 'User.email'],
            'afterFind' => function ($data) use ($accessible_widgets, $currentUserId) {
                foreach ($data as &$element) {
                    $element['Dashboard']['value'] = json_decode($element['Dashboard']['value'], true);
                    if (!$this->_isRest()) {
                        $widgets = [];
                        foreach ($element['Dashboard']['value'] as $val) {
                            $widgets[$val['widget']] = 1;
                        }
                        $element['Dashboard']['widgets'] = array_keys($widgets);
                        sort($element['Dashboard']['widgets']);
                        $temp = [];
                        foreach ($element['Dashboard']['widgets'] as $widget) {
                            if (in_array($widget, $accessible_widgets)) {
                                $temp['allow'][] = $widget;
                            } else {
                                $temp['deny'][] = $widget;
                            }
                        }
                        $element['Dashboard']['widgets'] = $temp;
                        if ($element['Dashboard']['user_id'] != $currentUserId) {
                            $element['User']['email'] = '';
                        }
                    }
                }
                return $data;
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('passedArgs', json_encode($this->passedArgs));
        $this->set('data', $this->viewVars['data']);
    }

    public function deleteTemplate($id)
    {
        $conditions = [];
        if (Validation::uuid($id)) {
            $conditions['Dashboard.uuid'] = $id;
        }
        if (!$this->_isSiteAdmin()) {
            $conditions['Dashboard.user_id'] = $this->Auth->user('id');
        }
        $params = [
            'conditions' => $conditions,
            'redirect' => $this->baseurl . '/dashboards/listTemplates'
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
