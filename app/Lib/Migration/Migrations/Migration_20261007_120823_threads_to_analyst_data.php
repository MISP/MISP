<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Convert event discussion threads into analyst data notes and drop their tables
 */
class Migration_20261007_120823_threads_to_analyst_data extends AbstractMigration
{
    public $description = 'Convert event discussion threads into analyst data notes and drop their tables';

    /**
     * Nothing the session data is built from changes.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const PAGE_SIZE = 500;

    const FALLBACK_NAMESPACE = 'b4c1e2a6-7d0f-4f3e-9a51-2c8e6d9f0b17';

    /** @var Note */
    private $Note;

    /** @var Log */
    private $Log;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $namespace;

    /** @var array Thread rows by id */
    private $threads = array();

    /** @var array Note target per thread id, false when the thread cannot be converted */
    private $targets = array();

    /** @var array Thread id by post id */
    private $postThreads = array();

    /** @var array Post ids carrying their thread's title */
    private $titleCarriers = array();

    /** @var array Cached rows by table and id, false when missing */
    private $rows = array('events' => array(), 'organisations' => array(), 'users' => array());

    private $counts = array(
        'converted' => 0,
        'existing' => 0,
        'dropped' => 0,
        'byOrgName' => 0,
        'deactivated' => 0,
        'workflows' => 0,
    );

    /**
     * Turn every discussion post into a Note on what its thread was about,
     * then remove the workflows listening on the post trigger. Notes are
     * written without callbacks: no audit entries, workflow runs or
     * owner overrides from a CLI user. Their uuids derive from the post id,
     * so a retry after a failed run skips what already landed.
     *
     * @return bool
     */
    public function beforeUp()
    {
        $hasThreads = $this->inspector()->hasTable('threads');
        $hasPosts = $this->inspector()->hasTable('posts');
        if (!$hasThreads && !$hasPosts) {
            return true;
        }
        $this->Note = ClassRegistry::init('Note');
        $this->Log = ClassRegistry::init('Log');
        $this->db = $this->Note->getDataSource();
        $this->namespace = $this->uuidNamespace();

        if ($hasThreads) {
            $this->loadThreads();
        }
        if ($hasPosts) {
            $this->loadPostTree();
            if (!$this->convertPosts()) {
                return false;
            }
        }
        $this->removePostWorkflows();
        $this->stripDiscussionColumn();
        $this->logSummary();
        return true;
    }

    /**
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        foreach (array('posts', 'threads') as $table) {
            if ($this->inspector()->hasTable($table)) {
                $schema->dropTable($table);
            }
        }
    }

    /**
     * @return void
     */
    private function loadThreads()
    {
        $columns = array('id', 'event_id', 'title', 'distribution', 'sharing_group_id', 'org_id');
        foreach ($this->select('threads', $columns) as $thread) {
            $this->threads[(int)$thread['id']] = $thread;
        }
        $this->preload('events', array_column($this->threads, 'event_id'));
        $this->preload('organisations', array_column($this->threads, 'org_id'));
        foreach ($this->threads as $id => $thread) {
            $this->targets[$id] = $this->resolveTarget($thread);
        }
    }

    /**
     * What a thread's notes hang on and who may see them. Visibility is the
     * event's, as thread access always followed the event, capped at this
     * community so that converting never makes a discussion travel.
     *
     * @param array $thread
     * @return array|false
     */
    private function resolveTarget(array $thread)
    {
        if ((int)$thread['event_id'] > 0) {
            $event = $this->row('events', $thread['event_id']);
            if (!$event) {
                return false;
            }
            $target = array('object_type' => 'Event', 'object_uuid' => $event['uuid']);
            $distribution = (int)$event['distribution'];
            $ownerOrgId = $event['org_id'];
        } else {
            $org = $this->row('organisations', $thread['org_id']);
            if (!$org) {
                return false;
            }
            $target = array('object_type' => 'Organisation', 'object_uuid' => $org['uuid']);
            $distribution = (int)$thread['distribution'];
            $ownerOrgId = $thread['org_id'];
        }
        // A sharing group would push to its servers: keep those to the owner org.
        $target['distribution'] = in_array($distribution, array(1, 2, 3), true) ? 1 : 0;
        $ownerOrg = $this->row('organisations', $ownerOrgId);
        $target['owner_org_uuid'] = $ownerOrg ? $ownerOrg['uuid'] : null;
        $threadOrg = $this->row('organisations', $thread['org_id']);
        $target['thread_org_uuid'] = $threadOrg ? $threadOrg['uuid'] : null;
        return $target;
    }

    /**
     * Map each post to its thread and pick, for threads that are not about an
     * event, the first top-level post: it carries the thread's title.
     *
     * @return void
     */
    private function loadPostTree()
    {
        $replies = array();
        $lastId = 0;
        do {
            $rows = $this->select('posts', array('id', 'thread_id', 'post_id'), $lastId);
            foreach ($rows as $row) {
                $lastId = (int)$row['id'];
                $this->postThreads[$lastId] = (int)$row['thread_id'];
                $replies[$lastId] = (int)$row['post_id'];
            }
        } while (count($rows) === self::PAGE_SIZE);

        foreach ($this->postThreads as $postId => $threadId) {
            if (
                empty($this->threads[$threadId]) ||
                (int)$this->threads[$threadId]['event_id'] > 0 ||
                isset($this->titleCarriers[$threadId]) ||
                $this->parentOf($postId, $threadId, $replies[$postId]) !== null
            ) {
                continue;
            }
            $this->titleCarriers[$threadId] = $postId;
        }
        $this->titleCarriers = array_flip($this->titleCarriers);
    }

    /**
     * @param int $postId
     * @param int $threadId
     * @param int $replyTo
     * @return int|null The post this one answers, when it is still there.
     */
    private function parentOf($postId, $threadId, $replyTo)
    {
        if ($replyTo > 0 && $replyTo !== $postId && isset($this->postThreads[$replyTo]) && $this->postThreads[$replyTo] === $threadId) {
            return $replyTo;
        }
        return null;
    }

    /**
     * @return bool
     */
    private function convertPosts()
    {
        $disclose = !empty(Configure::read('Security.disclose_user_emails'));
        $hostOrg = $this->row('organisations', Configure::read('MISP.host_org_id'));
        $columns = array('id', 'date_created', 'date_modified', 'user_id', 'contents', 'post_id', 'thread_id');
        $lastId = 0;
        do {
            $rows = $this->select('posts', $columns, $lastId);
            if (empty($rows)) {
                break;
            }
            $lastId = (int)end($rows)['id'];
            $this->preload('users', array_column($rows, 'user_id'));
            $this->preload('organisations', array_column($this->usersOf($rows), 'org_id'));
            $existing = $this->existingNotes(array_map(function ($row) {
                return $this->noteUuid($row['id']);
            }, $rows));

            $notes = array();
            foreach ($rows as $row) {
                $postId = (int)$row['id'];
                $threadId = (int)$row['thread_id'];
                $uuid = $this->noteUuid($postId);
                if (isset($existing[$uuid])) {
                    $this->counts['existing']++;
                    continue;
                }
                $user = $this->row('users', $row['user_id']);
                $authorOrg = $user ? $this->row('organisations', $user['org_id']) : false;
                $target = isset($this->targets[$threadId]) ? $this->targets[$threadId] : false;
                if (!$target) {
                    $this->logDroppedPost($row, $user, $authorOrg, $this->dropReason($threadId));
                    continue;
                }

                if ($authorOrg) {
                    $orgcUuid = $authorOrg['uuid'];
                    $authors = $disclose ? $user['email'] : $authorOrg['name'];
                    if (!$disclose) {
                        $this->counts['byOrgName']++;
                    }
                } else {
                    $orgcUuid = $hostOrg ? $hostOrg['uuid'] : ($target['thread_org_uuid'] ?: $target['owner_org_uuid']);
                    $authors = ($user && $disclose) ? $user['email'] : __('Deactivated user');
                    $this->counts['deactivated']++;
                }
                if (empty($orgcUuid)) {
                    $this->logDroppedPost($row, $user, $authorOrg, __('no organisation is left to own it'));
                    continue;
                }

                $parent = $this->parentOf($postId, $threadId, (int)$row['post_id']);
                $text = $this->convertMarkup($row['contents']);
                if (isset($this->titleCarriers[$postId])) {
                    $text = trim($this->threads[$threadId]['title']) . "\n\n" . $text;
                }
                $notes[] = array(
                    'uuid' => $uuid,
                    'object_uuid' => $parent === null ? $target['object_uuid'] : $this->noteUuid($parent),
                    'object_type' => $parent === null ? $target['object_type'] : 'Note',
                    'authors' => $authors,
                    'orgc_uuid' => $orgcUuid,
                    'org_uuid' => ($target['distribution'] === 0 && $target['owner_org_uuid']) ? $target['owner_org_uuid'] : $orgcUuid,
                    'created' => $this->dateOrNow($row['date_created']),
                    'modified' => $this->dateOrNow($row['date_modified']),
                    'distribution' => $target['distribution'],
                    'sharing_group_id' => null,
                    'note' => $text,
                );
            }
            if (!empty($notes)) {
                $saved = $this->Note->saveMany($notes, array(
                    'validate' => false,
                    'callbacks' => false,
                    'atomic' => true,
                ));
                if (!$saved) {
                    return false;
                }
                $this->counts['converted'] += count($notes);
            }
        } while (count($rows) === self::PAGE_SIZE);
        return true;
    }

    /**
     * @param int $threadId
     * @return string
     */
    private function dropReason($threadId)
    {
        if (empty($this->threads[$threadId])) {
            return __('its thread #%s no longer exists', $threadId);
        }
        $thread = $this->threads[$threadId];
        if ((int)$thread['event_id'] > 0) {
            return __('its event #%s no longer exists', $thread['event_id']);
        }
        return __('the organisation that started its thread no longer exists');
    }

    /**
     * Rewrite the discussion markup into plain text, as notes are shown
     * verbatim. Tags that do not pair up are left as they are.
     *
     * @param string $text
     * @return string
     */
    private function convertMarkup($text)
    {
        $text = str_replace(array("\r\n", "\r"), "\n", (string)$text);

        $innermostQuote = '/\[quote\]((?:(?!\[quote\]).)*?)\[\/quote\]/is';
        while (preg_match($innermostQuote, $text)) {
            $converted = preg_replace_callback($innermostQuote, function ($match) {
                $lines = explode("\n", trim($match[1]));
                $lines = array_map(function ($line) {
                    return rtrim('> ' . $line);
                }, $lines);
                return "\n" . implode("\n", $lines) . "\n\n";
            }, $text);
            if ($converted === null) {
                break;
            }
            $text = $converted;
        }

        $replacements = array(
            'event' => function ($inner) {
                return $this->eventReference($inner);
            },
            'thread' => function ($inner) {
                return $this->threadReference($inner);
            },
            'link' => function ($inner) {
                return trim($inner);
            },
            'code' => function ($inner) {
                return $inner;
            },
        );
        foreach ($replacements as $tag => $replace) {
            $converted = preg_replace_callback(
                sprintf('/\[%1$s\](.*?)\[\/%1$s\]/is', $tag),
                function ($match) use ($replace) {
                    $result = $replace($match[1]);
                    return $result === null ? $match[0] : $result;
                },
                $text
            );
            if ($converted !== null) {
                $text = $converted;
            }
        }
        return trim(preg_replace("/\n{3,}/", "\n\n", $text));
    }

    /**
     * @param string $id
     * @return string|null
     */
    private function eventReference($id)
    {
        $id = trim($id);
        if (!ctype_digit($id)) {
            return null;
        }
        $event = $this->row('events', $id);
        return $event ? __('Event %s', $event['uuid']) : __('Event #%s', $id);
    }

    /**
     * @param string $id
     * @return string|null
     */
    private function threadReference($id)
    {
        $id = trim($id);
        if (!ctype_digit($id)) {
            return null;
        }
        if (empty($this->threads[(int)$id])) {
            return __('Discussion #%s', $id);
        }
        $thread = $this->threads[(int)$id];
        if ((int)$thread['event_id'] > 0) {
            return $this->eventReference($thread['event_id']);
        }
        return __('Discussion "%s"', trim($thread['title']));
    }

    /**
     * Workflows on a trigger that no longer exists can never run again; keep
     * what they did in the log before deleting them.
     *
     * @return void
     */
    private function removePostWorkflows()
    {
        if (!$this->inspector()->hasTable('workflows')) {
            return;
        }
        $workflows = $this->select(
            'workflows',
            array('id', 'uuid', 'name', 'description', 'data'),
            null,
            array('trigger_id' => 'post-after-save')
        );
        if (empty($workflows)) {
            return;
        }
        $Workflow = ClassRegistry::init('Workflow');
        foreach ($workflows as $workflow) {
            $this->writeLog(
                'Workflow',
                (int)$workflow['id'],
                __('Removed workflow "%s" (%s): its trigger post-after-save no longer exists', $workflow['name'], $workflow['uuid']),
                (string)$workflow['data']
            );
            try {
                $Workflow->delete((int)$workflow['id']);
            } catch (Exception $e) {
                $Workflow->deleteAll(array('Workflow.id' => (int)$workflow['id']), false, false);
            }
            $this->counts['workflows']++;
        }
    }

    /**
     * @return void
     */
    private function stripDiscussionColumn()
    {
        $settings = $this->select(
            'user_settings',
            array('id', 'value'),
            null,
            array('setting' => 'event_index_hide_columns')
        );
        $UserSetting = ClassRegistry::init('UserSetting');
        foreach ($settings as $setting) {
            $columns = json_decode($setting['value'], true);
            if (!is_array($columns) || !in_array('discussion', $columns, true)) {
                continue;
            }
            $columns = array_values(array_diff($columns, array('discussion')));
            $UserSetting->save(
                array('UserSetting' => array('id' => (int)$setting['id'], 'value' => json_encode($columns))),
                array('validate' => false, 'callbacks' => false, 'fieldList' => array('value'))
            );
        }
    }

    /**
     * @param array $post
     * @param array|false $user
     * @param array|false $authorOrg
     * @param string $reason
     * @return void
     */
    private function logDroppedPost(array $post, $user, $authorOrg, $reason)
    {
        $threadId = (int)$post['thread_id'];
        $thread = isset($this->threads[$threadId]) ? sprintf('#%s "%s"', $threadId, trim($this->threads[$threadId]['title'])) : '#' . $threadId;
        $this->writeLog(
            'Thread',
            $threadId,
            __(
                'Discussion post #%s by %s (%s) on %s, thread %s, not migrated: %s',
                $post['id'],
                $user ? $user['email'] : __('Deactivated user'),
                $authorOrg ? $authorOrg['name'] : __('unknown organisation'),
                $post['date_created'],
                $thread,
                $reason
            ),
            (string)$post['contents']
        );
        $this->counts['dropped']++;
    }

    /**
     * @return void
     */
    private function logSummary()
    {
        $change = array(
            __('Notes created: %s', $this->counts['converted']),
            __('Already migrated by an earlier run: %s', $this->counts['existing']),
            __('Posts not migrated, each logged on its own: %s', $this->counts['dropped']),
            __('Authors shown by organisation name, as Security.disclose_user_emails is off: %s', $this->counts['byOrgName']),
            __('Posts by deactivated users: %s', $this->counts['deactivated']),
            __('Workflows on the post-after-save trigger removed: %s', $this->counts['workflows']),
        );
        $this->writeLog(
            'Thread',
            0,
            __('Converted %s discussion posts into analyst data notes', $this->counts['converted']),
            implode("\n", $change)
        );
    }

    /**
     * @param string $model
     * @param int $modelId
     * @param string $title
     * @param string $change
     * @return void
     */
    private function writeLog($model, $modelId, $title, $change)
    {
        $this->Log->create();
        $this->Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => $model,
            'model_id' => $modelId,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => $title,
            'change' => $change,
        ));
    }

    /**
     * @param string $table
     * @param array $columns
     * @param int|null $afterId Fetch the page of ids above this one, or everything when null.
     * @param array $equals Column => value conditions.
     * @param array $ids Restrict to these ids.
     * @return array
     */
    private function select($table, array $columns, $afterId = null, array $equals = array(), array $ids = array())
    {
        $where = array();
        foreach ($equals as $column => $value) {
            $where[] = $this->db->name($column) . ' = ' . $this->db->value($value, 'string');
        }
        if (!empty($ids)) {
            $where[] = $this->db->name('id') . ' IN (' . implode(', ', array_map('intval', $ids)) . ')';
        }
        $paged = $afterId !== null;
        if ($paged) {
            $where[] = $this->db->name('id') . ' > ' . (int)$afterId;
        }
        $sql = sprintf(
            'SELECT %s FROM %s%s ORDER BY %s%s',
            implode(', ', array_map(array($this->db, 'name'), $columns)),
            $this->db->name($table),
            empty($where) ? '' : ' WHERE ' . implode(' AND ', $where),
            $this->db->name('id'),
            $paged ? ' LIMIT ' . self::PAGE_SIZE : ''
        );
        $rows = array();
        foreach ((array)$this->Note->query($sql, false) as $row) {
            $rows[] = array_merge(...array_values($row));
        }
        return $rows;
    }

    /**
     * @param string $table
     * @param array $ids
     * @return void
     */
    private function preload($table, array $ids)
    {
        $missing = array();
        foreach ($ids as $id) {
            $id = (int)$id;
            if ($id > 0 && !array_key_exists($id, $this->rows[$table])) {
                $missing[$id] = $id;
            }
        }
        if (empty($missing)) {
            return;
        }
        $columns = array(
            'events' => array('id', 'uuid', 'distribution', 'org_id'),
            'organisations' => array('id', 'uuid', 'name'),
            'users' => array('id', 'org_id', 'email'),
        );
        foreach (array_chunk($missing, 1000) as $chunk) {
            foreach ($chunk as $id) {
                $this->rows[$table][$id] = false;
            }
            foreach ($this->select($table, $columns[$table], null, array(), $chunk) as $row) {
                $this->rows[$table][(int)$row['id']] = $row;
            }
        }
    }

    /**
     * @param string $table
     * @param int|string|null $id
     * @return array|false
     */
    private function row($table, $id)
    {
        $id = (int)$id;
        if ($id <= 0) {
            return false;
        }
        $this->preload($table, array($id));
        return $this->rows[$table][$id];
    }

    /**
     * @param array $posts
     * @return array
     */
    private function usersOf(array $posts)
    {
        $users = array();
        foreach ($posts as $post) {
            $user = $this->row('users', $post['user_id']);
            if ($user) {
                $users[] = $user;
            }
        }
        return $users;
    }

    /**
     * @param array $uuids
     * @return array Existing uuids as keys.
     */
    private function existingNotes(array $uuids)
    {
        $quoted = array_map(function ($uuid) {
            return $this->db->value($uuid, 'string');
        }, $uuids);
        $rows = $this->Note->query(sprintf(
            'SELECT %s FROM %s WHERE %s IN (%s)',
            $this->db->name('uuid'),
            $this->db->name('notes'),
            $this->db->name('uuid'),
            implode(', ', $quoted)
        ), false);
        $existing = array();
        foreach ((array)$rows as $row) {
            $existing[array_merge(...array_values($row))['uuid']] = true;
        }
        return $existing;
    }

    /**
     * @param string|null $date
     * @return string
     */
    private function dateOrNow($date)
    {
        if (empty($date) || strpos($date, '0000-00-00') === 0) {
            return date('Y-m-d H:i:s');
        }
        return $date;
    }

    /**
     * @return string
     */
    private function uuidNamespace()
    {
        $instance = Configure::read('MISP.uuid');
        if (!empty($instance) && Validation::uuid($instance)) {
            return $instance;
        }
        $hostOrg = $this->row('organisations', Configure::read('MISP.host_org_id'));
        return $hostOrg ? $hostOrg['uuid'] : self::FALLBACK_NAMESPACE;
    }

    /**
     * RFC 4122 version 5 uuid of the post id in this instance's namespace.
     *
     * @param int|string $postId
     * @return string
     */
    private function noteUuid($postId)
    {
        $hash = sha1(hex2bin(str_replace('-', '', $this->namespace)) . 'post:' . (int)$postId);
        return sprintf(
            '%s-%s-%04x-%04x-%s',
            substr($hash, 0, 8),
            substr($hash, 8, 4),
            (hexdec(substr($hash, 12, 4)) & 0x0fff) | 0x5000,
            (hexdec(substr($hash, 16, 4)) & 0x3fff) | 0x8000,
            substr($hash, 20, 12)
        );
    }
}
