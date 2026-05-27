<?php

App::uses('SessionStore', 'Lib/Dashboard/Tools');

/**
 * Logged-in users widget (dashboard v2).
 *
 * Lists the users that currently hold an active session, with how many
 * sessions each one has. "Currently logged in" is read from the live
 * session store — there is no engine-agnostic way to enumerate sessions
 * (PHP's SessionHandlerInterface / CakeSession are per-id: read/write/
 * destroy a known id, never "list all"), so enumeration is necessarily
 * backend-specific.
 *
 * Scope (deliberately narrow): only the **PHP → Redis** session engine
 * (`session.save_handler = redis`, the phpredis native handler) is
 * supported. For any other engine (files, database, memcached, apcu, a
 * Cake cache/database handler) the widget reports that the engine is
 * unsupported rather than guessing. Redis is the one store this MISP is
 * configured for and the one cleanly + safely enumerable here.
 *
 * Mechanism: the SessionStore tool (app/Lib/Dashboard/Tools) connects to
 * the session store, SCANs the session-key prefix, and tallies sessions
 * per authenticated user id (CakePHP stores it at Auth.User.id; only the
 * id is read — no token or payload). This widget loads those users for
 * display. The same tool backs the per-user session purge
 * (DashboardsController::invalidateUserSessions, DD-36), so the count
 * shown here and the purge agree by construction.
 *
 * Site-admin only (it reveals who is logged in across the instance).
 */
class LoggedInUsersWidget
{
    public $title = 'Logged-in users';
    public $category = 'users';
    // UserList render kind (DD-35): a people list — avatar (org logo →
    // initials chip) + email + org·role meta + a session-count badge.
    public $render = 'UserList';
    public $width = 3;
    public $height = 4;
    public $params = array();
    public $schema = array();
    public $description = 'Users that currently hold an active session, with their session count. Requires the PHP → Redis session engine.';
    // Live view; let the board re-scan once a minute (a SCAN + GET per
    // session is cheap, but not free — don't hammer it).
    public $autoRefreshDelay = 60;

    private $User = null;

    public function handler($user, $options = array())
    {
        if (!SessionStore::isSupported()) {
            // Message rows render full-width + centred in the UserList
            // kind. Raw values only — the renderer escapes once.
            return array(array(
                'type' => 'message',
                'title' => __('Unsupported session engine'),
                'value' => sprintf(
                    __('this widget requires the PHP → Redis session engine (current: %s)'),
                    SessionStore::handlerName()
                ),
            ));
        }

        $store = new SessionStore();
        if (!$store->connect()) {
            return array(array(
                'type' => 'message',
                'title' => __('Session store unreachable'),
                'value' => __('could not connect to the Redis session store'),
            ));
        }

        $counts = $store->tally();
        if (empty($counts)) {
            return array(array(
                'type' => 'message',
                'title' => __('No active sessions'),
                'value' => __('no users are currently logged in'),
            ));
        }

        return $this->buildRows($counts);
    }

    /**
     * Turn the per-user session tally into UserList rows: a summary
     * header, then one row per user (most sessions first), each an avatar
     * (org logo → initials chip) + email + org·role meta + a session-count
     * badge, linking to the user's admin view.
     */
    private function buildRows(array $counts)
    {
        $this->User = ClassRegistry::init('User');
        $users = $this->User->find('all', array(
            'recursive' => -1,
            // id + uuid feed the renderer's org-logo avatar lookup; name
            // feeds the meta line + initials-chip fallback.
            'contain' => array(
                'Organisation' => array('fields' => array('id', 'name', 'uuid')),
                'Role.name',
            ),
            'fields' => array('User.id', 'User.email', 'User.disabled', 'User.org_id'),
            'conditions' => array('User.id' => array_keys($counts)),
        ));
        $byId = array();
        foreach ($users as $u) {
            $byId[$u['User']['id']] = $u;
        }

        // Most sessions first, then by id for stability.
        uksort($counts, function ($a, $b) use ($counts) {
            if ($counts[$a] !== $counts[$b]) {
                return $counts[$b] - $counts[$a];
            }
            return (int)$a - (int)$b;
        });

        $totalSessions = array_sum($counts);
        $rows = array(array(
            'type' => 'header',
            'value' => sprintf(
                __('%d user%s online · %d session%s'),
                count($counts),
                count($counts) === 1 ? '' : 's',
                $totalSessions,
                $totalSessions === 1 ? '' : 's'
            ),
        ));

        foreach ($counts as $id => $count) {
            if (!isset($byId[$id])) {
                // A session for a user that no longer exists (e.g. deleted).
                $rows[] = array(
                    'type' => 'user',
                    'name' => sprintf(__('User #%s'), $id),
                    'meta' => __('account removed'),
                    'badge' => $count,
                    'muted' => true,
                );
                continue;
            }
            $u = $byId[$id];
            $orgName = !empty($u['Organisation']['name']) ? $u['Organisation']['name'] : '—';
            $role = !empty($u['Role']['name']) ? $u['Role']['name'] : '—';
            $meta = $orgName . ' · ' . $role;
            // A disabled account holding a live session is notable (a
            // possibly-stale session) — flag it and dim the row.
            if (!empty($u['User']['disabled'])) {
                $meta .= ' · ' . __('disabled');
            }
            // Raw values only — the UserList renderer escapes once (a
            // malicious org/role name is rendered as inert text there).
            $rows[] = array(
                'type' => 'user',
                'name' => $u['User']['email'],
                'meta' => $meta,
                'badge' => $count,
                'muted' => !empty($u['User']['disabled']),
                'org' => array(
                    'id'   => isset($u['Organisation']['id']) ? $u['Organisation']['id'] : null,
                    'name' => isset($u['Organisation']['name']) ? $u['Organisation']['name'] : '',
                    'uuid' => isset($u['Organisation']['uuid']) ? $u['Organisation']['uuid'] : '',
                ),
                'drilldown' => '/admin/users/view/' . (int)$id,
            );
        }
        return $rows;
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
