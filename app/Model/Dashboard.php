<?php
App::uses('AppModel', 'Model');
class Dashboard extends AppModel
{
    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'user_id' => 'numeric',
        'org_id' => 'numeric',
        'role_id' => 'numeric',
        'uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
        )
    );

    public $belongsTo = array(
        'User',
        'Role',
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        )
    );

    /**
     * @param array $user
     * @param string $name
     * @param bool $returnOnException
     * @return false|mixed
     */
    public function loadWidget(array $user, $name, $returnOnException = false)
    {
        $name = str_replace('/', '', $name);
        if (file_exists(APP . 'Lib/Dashboard/' . $name . '.php')) {
            App::uses($name, 'Dashboard');
        } else if (file_exists(APP . 'Lib/Dashboard/Custom/' . $name . '.php')) {
            App::uses($name, 'Dashboard/Custom');
        } else {
            $found = false;
            if (file_exists(APP . 'Lib/Dashboard/Custom')) {
                App::uses('Folder', 'Utility');
                $customdir = new Folder(APP . 'Lib/Dashboard/Custom');
                $subDirectories = $customdir->read();
                foreach ($subDirectories[0] as $subDir) {
                    if (file_exists(APP . 'Lib/Dashboard/Custom/' . $subDir . '/' . $name . '.php')) {
                        App::uses($name, 'Dashboard/Custom/' . $subDir);
                        $found = true;
                        break;
                    }
                }
            }
            if (!$found) {
                if ($returnOnException) {
                    return false;
                }
                throw new NotFoundException(__('Invalid widget or widget not found.'));
            }
        }
        $widget = new $name();
        if (method_exists($widget, 'checkPermissions') && !$widget->checkPermissions($user)) {
            if ($returnOnException) {
                return false;
            }
            throw new NotFoundException(__('Invalid widget or widget not found.'));
        }
        return $widget;
    }

    public function loadAllWidgets($user)
    {
        $paths = array(
            '/',
            '/Custom'
        );
        App::uses('Folder', 'Utility');
        $customdir = new Folder(APP . 'Lib/Dashboard/Custom');
        $subDirectories = $customdir->read();
        foreach ($subDirectories[0] as $subDir) {
            $paths[] = '/Custom/' . $subDir;
        }
        $widgets = array();
        foreach ($paths as $path) {
            $currentDir = new Folder(APP . 'Lib/Dashboard' . $path);
            $widgetFiles = $currentDir->find('.*Widget\.php');
            foreach ($widgetFiles as $widgetFile) {
                $className = substr($widgetFile, 0, strlen($widgetFile) -4);
                $temp = $this->__extractMeta($user, $className, $path);
                if ($temp !== false) {
                    $widgets[$className] = $temp;
                }
            }
        }
        ksort($widgets);
        return $widgets;
    }

    private function __extractMeta($user, $className, $path)
    {
        App::uses($className, 'Dashboard' . ($path === '/' ? '' : $path));
        $widgetClass = new $className();
        if (method_exists($widgetClass, 'checkPermissions')) {
            if (!$widgetClass->checkPermissions($user)) {
                return false;
            }
        }
        $widget = array(
            'widget' => $className,
            'title' => $widgetClass->title,
            'render' => $widgetClass->render,
            'params' => empty($widgetClass->params) ? array() : $widgetClass->params,
            'description' => empty($widgetClass->description) ?  $widgetClass->title : $widgetClass->description,
            'height' => empty($widgetClass->height) ? 1 : $widgetClass->height,
            'width' => empty($widgetClass->width) ? 1 : $widgetClass->width,
            'placeholder' => empty($widgetClass->placeholder) ? '' : $widgetClass->placeholder,
            'autoRefreshDelay' => empty($widgetClass->autoRefreshDelay) ? false : $widgetClass->autoRefreshDelay,
        );
        return $widget;
    }

    public function import($user, $value, $targetUser = false)
    {
        $this->User = ClassRegistry::init('User');
        if (empty($targetUser)) {
            $targetUser = $user;
        } else if (!is_array($targetUser)) {
            $targetUser = $this->User->getAuthUser($targetUser);
        }
        if (empty($targetUser)) {
            throw new NotFoundException(__('Invalid user.'));
        }
        $settingsToSave = array();
        foreach ($value as $widgetConfig) {
            $widget = $this->loadWidget($targetUser, $widgetConfig['widget'], true);
            if (!empty($widget)) {
                $settingsToSave[] = $widgetConfig;
            }
        }
        $data = array(
            'UserSetting' => array(
                'user_id' => $targetUser['id'],
                'setting' => 'dashboard',
                // json_encode here because UserSetting's validate_json
                // validator runs before beforeValidate's array→string
                // coercion and JsonTool::isValid chokes on PHP arrays.
                // Mirrors the encode step at DashboardsController::
                // updateSettings and resetFromTemplate.
                'value' => json_encode($settingsToSave, JSON_UNESCAPED_SLASHES)
            )
        );
        return $this->User->UserSetting->setSetting($user, $data);
    }

    public function export($user)
    {
        $this->User = ClassRegistry::init('User');
        $data = $this->User->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'UserSetting.user_id' => $user['id'],
                'UserSetting.setting' => 'dashboard'
            )
        ));
        return $data;
    }

    public function getDashboardTemplate($user, $dashboard_id = false)
    {
        if (empty($dashboard_id)) {
            $conditions = array(
                'Dashboard.default' => 1
            );
        } else {
            if (Validation::uuid($dashboard_id)) {
                $conditions = array(
                    'Dashboard.uuid' => $dashboard_id
                );
            } else {
                $conditions = array(
                    'Dashboard.id' => $dashboard_id
                );
            }
        }
        $template = $this->find('first', array(
            'recursive' => -1,
            'conditions' => $conditions
        ));
        if (empty($template)) {
            return array();
        }
        if (empty($user['Role']['perm_site_admin'])) {
            if (
                $template['Dashboard']['user_id'] != $user['id'] &&
                (
                    empty($template['Dashboard']['selectable']) ||
                    (
                        !empty($template['Dashboard']['restrict_to_org_id']) &&
                        $template['Dashboard']['restrict_to_org_id'] != $user['org_id']
                    ) ||
                    (
                        !empty($template['Dashboard']['restrict_to_role_id']) &&
                        $template['Dashboard']['restrict_to_role_id'] != $user['role_id']
                    ) ||
                    (
                        !empty($template['Dashboard']['restrict_to_permission_flag']) &&
                        empty($user['role'][$template['Dashboard']['restrict_to_permission_flag']])
                    )
                )
            ) {
                return array();
            }
        }
        return $template;
    }

    public function saveDashboardTemplate($user, $settings, $update = false)
    {
        $this->User = ClassRegistry::init('User');
        $data = $this->User->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'UserSetting.user_id' => $user['id'],
                'UserSetting.setting' => 'dashboard'
            )
        ));
        $editableFields = array(
            'name',
            'description',
            'selectable',
            'value'
        );
        if ($user['Role']['perm_site_admin']) {
            $editableFields = array_merge(
                $editableFields,
                array(
                    'default',
                    'restrict_to_role_id',
                    'restrict_to_permission_flag',
                    'restrict_to_org_id'
                )
            );
        }
        if ($update) {
            $existingDashboard = $this->getDashboardTemplate($user, $update);
            if (empty($existingDashboard)) {
                throw new NotFoundException(__('Invalid dashboard template.'));
            }
            $data = $existingDashboard['Dashboard'];
        } else {
            $this->create();
            $data = array(
                'user_id' => $user['id'],
                'uuid' => CakeText::uuid()
            );
            if (empty($user['role']['perm_site_admin'])) {
                $data['restrict_to_org_id'] = $user['org_id'];
            }
        }
        foreach ($editableFields as $editable) {
            if (isset($settings[$editable])) {
                $data[$editable] = $settings[$editable];
            }
        }
        $data['timestamp'] = time();
        if (is_array($data['value'])) {
            $data['value'] = json_encode($data['value']);
        }
        if (!empty($data['default'])) {
            $this->__unsetPreviousDefault();
        }
        return $this->save(array('Dashboard' => $data));
    }

    private function __unsetPreviousDefault()
    {
        $currentDefault = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'Dashboard.default' => 1
            )
        ));
        if (!empty($currentDefault)) {
            $currentDefault['Dashboard']['default'] = 0;
            $this->save($currentDefault);
        }
        return true;
    }

    /**
     * Import the dashboard templates that ship with MISP from
     * app/files/dashboard-templates/<slug>/template.json into the
     * `dashboards` table as built-in starter templates (DD-22). Mirrors
     * the warninglist/taxonomy/object-template on-demand ingest: glob the
     * shipped directory, read each manifest, upsert a row.
     *
     * Built-ins are owned by the system (user_id = 0) — the gallery's
     * "starter" marker — and are always `selectable` so they surface for
     * every permitted user; they are never the global `default` board.
     *
     * Re-ingest is idempotent and version-free: each manifest carries a
     * fixed `uuid` and the row is upserted on that uuid (overwrite, no
     * version gate). Shipped templates are read-only reference data, so
     * an overwrite loses nothing a user authored — a user's own board
     * (a UserSetting) and any template they cloned are separate rows.
     *
     * Pruning of orphaned built-ins (rows whose manifest no longer ships)
     * is opt-in via $prune — the explicit admin/CLI ingest passes true; the
     * silent auto-ingest on update (DD-24) leaves it false, so an update
     * never deletes a dashboard. See the prune block for its guards.
     *
     * If a manifest declares `default_fallback` and the instance has no
     * template flagged as the global default, that candidate is promoted to
     * default so fresh users get a sensible board (DD-26). This fills an
     * empty slot only — an admin's existing default is never overridden.
     *
     * @param string|null $dir source directory (defaults to the shipped
     *                          one; overridable for tests)
     * @param bool $prune delete built-ins whose manifest no longer ships
     * @return array ['success' => [id => ['name' => …]], 'fails' => [slug => msg];
     *               'pruned' => [id => name] when $prune removed rows;
     *               'promoted_default' => [id => name] when a fallback was set]
     */
    public function importTemplatesFromDirectory($dir = null, $prune = false)
    {
        App::uses('FileAccessTool', 'Tools');
        if ($dir === null) {
            $dir = APP . 'files' . DS . 'dashboard-templates';
        }
        $result = array('success' => array(), 'fails' => array());
        if (!is_dir($dir)) {
            return $result;
        }
        $shippedUuids = array();
        $fallbackUuids = array();
        $manifests = glob($dir . DS . '*' . DS . 'template.json');
        foreach ($manifests as $path) {
            $slug = basename(dirname($path));
            try {
                $template = FileAccessTool::readJsonFromFile($path, true);
                // Collect the uuid even if the import below fails (e.g. a
                // transient save error) so a still-shipped template is
                // never mistaken for an orphan and pruned.
                if (!empty($template['uuid'])) {
                    $shippedUuids[] = $template['uuid'];
                    // A manifest may declare itself the fallback default
                    // (DD-26): promoted to the global default below, but
                    // only when the instance has no default set.
                    if (!empty($template['default_fallback'])) {
                        $fallbackUuids[] = $template['uuid'];
                    }
                }
                $id = $this->__importTemplate($template);
                $result['success'][$id] = array('name' => $template['name']);
            } catch (Exception $e) {
                $result['fails'][$slug] = $e->getMessage();
            }
        }
        // Prune orphaned built-ins, making the shipped set authoritative.
        // Guards: only when $prune is set (the explicit admin/CLI ingest);
        // never when no manifest was found (an empty/unreadable dir must not
        // wipe every built-in); only user_id=0 (built-ins — saveDashboard-
        // Template always uses a real user_id, so user boards are never 0)
        // and default=0 (never delete the active global default, even if an
        // admin promoted a built-in to it). Delete by id one-by-one because
        // Dashboard's belongsTo Organisation foreign key (org_id) is phantom
        // — deleteAll()/updateAll()'s auto-join references a non-existent
        // column and crashes.
        if ($prune && !empty($shippedUuids)) {
            $orphans = $this->find('list', array(
                'recursive' => -1,
                'conditions' => array(
                    'Dashboard.user_id' => 0,
                    'Dashboard.default' => 0,
                    'NOT' => array('Dashboard.uuid' => $shippedUuids),
                ),
                'fields' => array('Dashboard.id', 'Dashboard.name'),
            ));
            foreach (array_keys($orphans) as $orphanId) {
                $this->delete($orphanId, false);
            }
            if (!empty($orphans)) {
                $result['pruned'] = $orphans;
            }
        }
        // Fallback default (DD-26): if a shipped manifest declares
        // default_fallback and the instance has NO template flagged default,
        // promote that candidate to the global default so a fresh
        // user lands on a sensible board instead of the empty state. Fires
        // on every ingest (explicit + the silent auto-ingest on update) but
        // only fills an empty slot — an admin's existing default (built-in
        // or otherwise) is preserved by the COUNT guard and by
        // __importTemplate's default-preservation. Single-default invariant
        // holds: we only set one, and only when none exists. saveField (not
        // updateAll) avoids the phantom org_id join.
        if (!empty($fallbackUuids)) {
            $hasDefault = $this->find('count', array(
                'recursive' => -1,
                'conditions' => array('Dashboard.default' => 1),
            ));
            if (empty($hasDefault)) {
                $candidate = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Dashboard.uuid' => $fallbackUuids),
                    'order' => array('Dashboard.id' => 'ASC'),
                    'fields' => array('Dashboard.id', 'Dashboard.name'),
                ));
                if (!empty($candidate)) {
                    $this->id = $candidate['Dashboard']['id'];
                    $this->saveField('default', 1);
                    $result['promoted_default'] = array(
                        $candidate['Dashboard']['id'] => $candidate['Dashboard']['name'],
                    );
                }
            }
        }
        return $result;
    }

    /**
     * Upsert a single shipped template (keyed on its fixed uuid) into the
     * `dashboards` table. Throws on a malformed manifest or a DB error so
     * importTemplatesFromDirectory() can record the per-template failure.
     */
    private function __importTemplate(array $template)
    {
        foreach (array('uuid', 'name', 'value') as $required) {
            if (empty($template[$required])) {
                throw new Exception(__('Missing required key "%s".', $required));
            }
        }
        if (!Validation::uuid($template['uuid'])) {
            throw new Exception(__('Invalid uuid.'));
        }
        if (!is_array($template['value'])) {
            throw new Exception(__('"value" must be an array of widget instances.'));
        }
        $existing = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Dashboard.uuid' => $template['uuid']),
            'fields' => array('Dashboard.id', 'Dashboard.default'),
        ));
        $data = array(
            'uuid' => $template['uuid'],
            'name' => $template['name'],
            'description' => isset($template['description']) ? $template['description'] : '',
            'user_id' => 0,
            'selectable' => isset($template['selectable']) ? (int)(bool)$template['selectable'] : 1,
            'restrict_to_org_id' => isset($template['restrict_to_org_id']) ? (int)$template['restrict_to_org_id'] : 0,
            'restrict_to_role_id' => isset($template['restrict_to_role_id']) ? (int)$template['restrict_to_role_id'] : 0,
            'restrict_to_permission_flag' => isset($template['restrict_to_permission_flag']) ? (string)$template['restrict_to_permission_flag'] : '',
            'value' => json_encode($template['value']),
            'timestamp' => time(),
        );
        if (!empty($existing)) {
            $data['id'] = $existing['Dashboard']['id'];
            // Preserve the existing default flag: an admin may have promoted
            // this built-in to the global default, and a re-ingest must not
            // silently demote it. (DD-26 refines DD-22's blanket default=0.)
            $data['default'] = (int)$existing['Dashboard']['default'];
        } else {
            $this->create();
            // A newly-shipped built-in never seizes the default slot on
            // insert; the fallback-default promotion (below, conditional on
            // no default existing) is the only path that sets default=1.
            $data['default'] = 0;
        }
        if (!$this->save(array('Dashboard' => $data))) {
            throw new Exception(__('Database error: %s', json_encode($this->validationErrors)));
        }
        return (int)$this->id;
    }
}
