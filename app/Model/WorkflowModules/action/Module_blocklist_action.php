<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_blocklist_action extends WorkflowBaseActionModule
{
    public $blocking = false;
    public $disabled = true;
    public $version = '0.8';
    public $id = 'blocklist-action-module';
    public $name = 'Update blocklist';
    public $description = 'Update a blocklist file with event attributes. Supports removal-by-tag, atomic writes with one-generation backup, and optional rolling filesystem snapshots.';
    public $icon = 'server';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    private $Attribute;
    private $User;

    public function __construct()
    {
        parent::__construct();
        $this->Attribute = ClassRegistry::init('Attribute');
        $this->User = ClassRegistry::init('User');

        $this->debugLog = false;

        $this->params = [
            [
                'id' => 'attributeTypesToInclude',
                'label' => __('List of attributes to include'),
                'type' => 'picker',
                'picker_create_new' => true,
                'placeholder' => '[\'ip-src\', \'ip-dst\', \'domain\', \'hostname\']',
            ],
            [
                'id' => 'blocklist',
                'label' => __('Filename of the blocklist (relative to webroot/misp-export)'),
                'required' => true,
                'type' => 'input',
            ],
            [
                'id' => 'exportFormat',
                'label' => __('Export format'),
                'type' => 'select',
                'default' => 'regex',
                'options' => [
                    'regex' => __('writes each indicator as *value* and adds a type=regex header'),
                    'paloalto' => __('writes each indicator as *value* and truncates lines to 255 characters'),
                    'firewall' => __('writes each indicator verbatim (one entry per line)'),
                ],
            ],
            [
                'id' => 'excludeWarninglist',
                'label' => __('Exclude attributes that match a warninglist (only affects additions)'),
                'type' => 'select',
                'default' => 'yes',
                'options' => [
                    'no' => __('No'),
                    'yes' => __('Yes'),
                ],
            ],
            [
                'id' => 'tagAttributeInBlocklist',
                'label' => __('Tag(s) to attach to attributes already in the blocklist'),
                'type' => 'picker',
                'multiple' => true,
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/0.json',
                ],
                'placeholder' => __('Pick one or more tags'),
            ],
            [
                'id' => 'removalTag',
                'label' => __('Remove from blocklist if attribute carries any of these tag(s)'),
                'type' => 'picker',
                'multiple' => true,
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/0.json',
                ],
                'placeholder' => __('Pick one or more tags'),
            ],
            [
                'id' => 'tagAttributeRemovedFromBlocklist',
                'label' => __('Tag(s) to attach to attributes after they are removed from the blocklist'),
                'type' => 'picker',
                'multiple' => true,
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/0.json',
                ],
                'placeholder' => __('Pick one or more tags'),
            ],
            [
                'id' => 'createSnapshot',
                'label' => __('Create a filesystem snapshot of the blocklist after each successful change'),
                'type' => 'select',
                'default' => 'no',
                'options' => [
                    'no' => __('No'),
                    'yes' => __('Yes'),
                ],
            ],
            [
                'id' => 'snapshotRetention',
                'label' => __('Maximum number of snapshots to keep (older ones are deleted)'),
                'type' => 'input',
                'default' => '10',
                'placeholder' => '10',
                'display_on' => [
                    'createSnapshot' => 'yes',
                ],
            ],
        ];

    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $user = $roamingData->getUser();

        // Strip path component, keep the resolved file in export dir.
        $blocklistFilename = basename((string)($params['blocklist']['value'] ?? ''));
        if ($blocklistFilename === '' || $blocklistFilename === '.' || $blocklistFilename === '..') {
            return $this->__fail(__('Blocklist filename is empty or invalid.'), $errors, $roamingData);
        }
        $exportDir = APP . 'webroot' . DS . 'misp-export';
        if (!is_dir($exportDir) && !@mkdir($exportDir, 0775, true) && !is_dir($exportDir)) {
            return $this->__fail(__('Failed to create export directory: %s', $exportDir), $errors, $roamingData);
        }
        $resolvedExportDir = realpath($exportDir);
        if ($resolvedExportDir === false) {
            return $this->__fail(__('Export directory does not exist: %s', $exportDir), $errors, $roamingData);
        }
        $blocklist = $resolvedExportDir . DS . $blocklistFilename;
        if (file_exists($blocklist)) {
            $resolvedBlocklist = realpath($blocklist);
            if ($resolvedBlocklist === false || strpos($resolvedBlocklist, $resolvedExportDir . DS) !== 0) {
                return $this->__fail(__('Blocklist path escapes the export directory.'), $errors, $roamingData);
            }
            $blocklist = $resolvedBlocklist;
        }

        $attributeTypesToInclude = $params['attributeTypesToInclude']['value'] ?? [];
        $tagAttributeInBlocklist = $this->__normaliseTagList($params['tagAttributeInBlocklist']['value'] ?? null);
        $removalTags = $this->__normaliseTagList($params['removalTag']['value'] ?? null);
        $tagAttributeRemovedFromBlocklist = $this->__normaliseTagList($params['tagAttributeRemovedFromBlocklist']['value'] ?? null);
        $excludeWarninglist = ($params['excludeWarninglist']['value'] ?? 'yes') === 'yes';
        $this->exportFormat = $params['exportFormat']['value'] ?? 'regex';

        $createSnapshot = ($params['createSnapshot']['value'] ?? 'no') === 'yes';
        $snapshotRetention = (int)($params['snapshotRetention']['value'] ?? 10);
        if ($snapshotRetention < 1) {
            $snapshotRetention = 1;
        }

        // Read the blocklist
        $blocklistExisting = $this->__readBlocklist($blocklist);
        $existingIndex = array_flip($blocklistExisting);

        // Extract the attributes from the event
        $attributes = $this->extractAttributes($rData['Event']['_AttributeFlattened'] ?? [], $attributeTypesToInclude);
        $this->__log(sprintf('Extracted %d attributes from event %s', count($attributes), $rData['Event']['id'] ?? 'unknown'));

        if (count($attributes) === 0) {
            $this->__notification(__('No attributes found to update the blocklist'), 'info', $roamingData);
            return true;
        }

        // Tags that, if present on an attribute, mean "remove from blocklist". The
        // configured removal trigger plus the "removed from blocklist" stamp itself,
        // so a previous run's stamp keeps being honoured by later workflow runs and
        // an attribute is never re-tagged "in list" after it has been removed.
        $effectiveRemovalTags = array_values(array_unique(array_merge($removalTags, $tagAttributeRemovedFromBlocklist)));

        $blocklistNew = [];
        $blocklistRemove = [];
        $blocklistAlreadyPresent = [];
        $blocklistSkipped = [];

        foreach ($attributes as $attribute) {
            $value = $attribute['value'];

            // Removal-by-tag
            if (!empty($effectiveRemovalTags) && $this->__attributeHasAnyTag($attribute, $effectiveRemovalTags)) {
                if (isset($existingIndex[$value])) {
                    $this->__log(sprintf('Attribute %s carries a removal tag, scheduling removal from blocklist', $value));
                    $blocklistRemove[$value] = $attribute;
                } else {
                    $this->__log(sprintf('Attribute %s carries a removal tag but is not in the blocklist, skipping', $value));
                }
                continue;
            }

            if (isset($existingIndex[$value])) {
                $blocklistAlreadyPresent[$value] = $attribute;
                if (!empty($tagAttributeInBlocklist)) {
                    $this->__log(sprintf('Attribute %s is already in the blocklist, tagging it', $value));
                    $tagAttached = [];
                    $options = ['tags' => $tagAttributeInBlocklist, 'local' => true, 'relationship_type' => ''];
                    $this->Attribute->attachTagsToAttributeAndTouch($attribute['id'], $attribute['event_id'], $options, $user, $tagAttached);
                }
                continue;
            }

            if ($excludeWarninglist && !empty($attribute['warnings'])) {
                $this->__log(sprintf('Attribute %s has warninglist hits, skipping addition', $value));
                $blocklistSkipped[$value] = $attribute;
                continue;
            }

            $blocklistNew[$value] = $attribute;
        }

        // Apply removals after the merge
        $blocklistUpdate = array_merge($blocklistExisting, array_keys($blocklistNew));
        if (!empty($blocklistRemove)) {
            $blocklistUpdate = array_diff($blocklistUpdate, array_keys($blocklistRemove));
        }
        $blocklistUpdate = array_values(array_unique($blocklistUpdate));
        sort($blocklistUpdate);

        $changed = !empty($blocklistNew) || !empty($blocklistRemove);
        $writeOk = true;
        $snapshotPath = null;

        if ($changed) {
            $writeOk = $this->__writeBlocklist($blocklist, $blocklistUpdate);
            if ($writeOk && $createSnapshot) {
                $snapshotPath = $this->__createSnapshot($blocklist);
                $this->__pruneSnapshots($blocklist, $snapshotRetention);
            }
        }

        // After a successful removal, also strip the "in blocklist" tag(s)
        $tagsToDetachOnRemoval = array_values(array_unique(array_merge($removalTags, $tagAttributeInBlocklist)));
        if ($writeOk && !empty($blocklistRemove) && (!empty($tagsToDetachOnRemoval) || !empty($tagAttributeRemovedFromBlocklist))) {
            foreach ($blocklistRemove as $attribute) {
                if (!empty($tagsToDetachOnRemoval)) {
                    $tagDetached = [];
                    $detachOptions = ['tags' => $tagsToDetachOnRemoval, 'local' => null];
                    $this->Attribute->detachTagsFromAttributeAndTouch($attribute['id'], $attribute['event_id'], $detachOptions, $tagDetached);
                    if (!empty($tagDetached)) {
                        $this->__log(sprintf('Detached tag(s) %s from attribute %s', implode(',', $tagDetached), $attribute['value']));
                    }
                }
                if (!empty($tagAttributeRemovedFromBlocklist)) {
                    $tagAttached = [];
                    $attachOptions = ['tags' => $tagAttributeRemovedFromBlocklist, 'local' => true, 'relationship_type' => ''];
                    $this->Attribute->attachTagsToAttributeAndTouch($attribute['id'], $attribute['event_id'], $attachOptions, $user, $tagAttached);
                    if (!empty($tagAttached)) {
                        $this->__log(sprintf('Attached "removed from blocklist" tag(s) %s to attribute %s', implode(',', $tagAttached), $attribute['value']));
                    }
                }
            }
        }

        // Notify the user.
        $eventInfo = $rData['Event']['info'] ?? 'unknown';
        if ($changed && $writeOk) {
            $message = __(
                'Blocklist "%s" updated from event "%s": %s indicator(s) added, %s already present, %s removed, %s skipped (warninglist).',
                $blocklist,
                $eventInfo,
                count($blocklistNew),
                count($blocklistAlreadyPresent),
                count($blocklistRemove),
                count($blocklistSkipped)
            );
            $variant = 'success';
        } elseif ($changed && !$writeOk) {
            $message = __('Failed to write blocklist "%s" from event "%s".', $blocklist, $eventInfo);
            $variant = 'danger';
            $errors[] = $message;
        } else {
            $message = __(
                'No changes applied to blocklist "%s" from event "%s" (%s indicator(s) already present, %s skipped (warninglist)).',
                $blocklist,
                $eventInfo,
                count($blocklistAlreadyPresent),
                count($blocklistSkipped)
            );
            $variant = 'info';
        }
        $this->__notification($message, $variant, $roamingData);

        // Expose the change-set in the roaming data
        $delta = [
            'blocklist' => $blocklist,
            'export_format' => $this->exportFormat,
            'added' => array_values($blocklistNew),
            'removed' => array_values($blocklistRemove),
            'already_present' => array_values($blocklistAlreadyPresent),
            'skipped_warninglist' => array_values($blocklistSkipped),
            'snapshot' => $snapshotPath,
            'written' => $changed && $writeOk,
        ];

        // Narrow Event.Attribute / _AttributeFlattened to the attributes this run touched
        $keepIds = array_flip(array_merge(
            array_column($blocklistNew, 'id'),
            array_column($blocklistAlreadyPresent, 'id')
        ));
        foreach (['Attribute', '_AttributeFlattened'] as $key) {
            if (empty($rData['Event'][$key]) || !is_array($rData['Event'][$key])) {
                continue;
            }
            $kept = [];
            foreach ($rData['Event'][$key] as $a) {
                if (isset($a['id'], $keepIds[$a['id']])) {
                    $kept[] = $a;
                }
            }
            $rData['Event'][$key] = $kept;
        }

        $rData['Event']['_blocklistDelta'] = $delta;
        $roamingData->setData($rData);

        return $writeOk;
    }

    /**
     * Tag picker param value (null / scalar / array) to tag names.
     */
    protected function __normaliseTagList($value): array
    {
        if ($value === null || $value === '' || $value === false) {
            return [];
        }
        $tags = array_map('trim', (array)$value);
        $tags = array_filter($tags, function ($t) {
            return $t !== '';
        });
        return array_values(array_unique($tags));
    }

    /**
     * True if the attribute carries any of the given tag names.
     */
    protected function __attributeHasAnyTag(array $attribute, array $tagNames): bool
    {
        foreach ($tagNames as $tagName) {
            if ($this->__attributeHasTag($attribute, $tagName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Copies the blocklist file to a timestamped snapshot next to the original.
     */
    protected function __createSnapshot(string $blocklist): ?string
    {
        if (!is_readable($blocklist)) {
            return null;
        }
        $snapshot = $blocklist . '.snapshot-' . date('Ymd-His') . '-' . bin2hex(random_bytes(3));
        if (!@copy($blocklist, $snapshot)) {
            $this->__log('Failed to create snapshot: ' . $snapshot);
            return null;
        }
        $this->__log('Snapshot created: ' . $snapshot);
        return $snapshot;
    }

    /**
     * Keeps only the $keep newest snapshots for the given blocklist
     */
    protected function __pruneSnapshots(string $blocklist, int $keep): void
    {
        $matches = glob($blocklist . '.snapshot-*');
        if (!is_array($matches) || count($matches) <= $keep) {
            return;
        }
        usort($matches, function ($a, $b) {
            return filemtime($b) <=> filemtime($a);
        });
        foreach (array_slice($matches, $keep) as $old) {
            if (@unlink($old)) {
                $this->__log('Pruned old snapshot: ' . $old);
            } else {
                $this->__log('Failed to prune old snapshot: ' . $old);
            }
        }
    }

    /**
     * Transform values, such as removing http/https from URLs
     *
     * @param string $value attribute value to transform.
     * @return string Transformed value
     */
    protected function __transformValue(string $value): string
    {
        $value = trim($value);
        $value = preg_replace('#^https?://#', '', $value);
        return $value;
    }

    /**
     * Extracts attributes from the provided array that match the specified types and have to_ids set to 1.
     *
     * @param array $attributes Array of attribute arrays to filter.
     * @param array $attribute_types_to_include List of attribute types to include.
     * @return array Filtered list of attributes with relevant fields.
     */
    protected function extractAttributes(array $attributes, array $attribute_types_to_include): array
    {
        $result =  [];
        foreach ($attributes as $attribute) {
            // Only include attributes of the specified types and with to_ids set to 1
            if (isset($attribute['type']) && in_array($attribute['type'], $attribute_types_to_include)
                    && isset($attribute['to_ids']) && $attribute['to_ids'] == 1) {

                // Get the warnings if they exist
                $warnings = false;
                if (isset($attribute['warnings']) && is_array($attribute['warnings']) && count($attribute['warnings']) > 0) {
                    $warnings = true;
                    // Log the warnings for debugging purposes
                    $this->__log($attribute['warnings'], true);
                }

                // Transform the value
                $value = $this->__transformValue($attribute['value']);
                // Build the attribute result array with relevant fields.
                $result[] = array(
                    'id' => $attribute['id'],
                    'uuid' => $attribute['uuid'],
                    'value' => $value,
                    'event_id' => $attribute['event_id'],
                    'Tag' => isset($attribute['Tag']) && is_array($attribute['Tag']) ? $attribute['Tag'] : [],
                    '_allTags' => isset($attribute['_allTags']) && is_array($attribute['_allTags']) ? $attribute['_allTags'] : [],
                    'warnings' => $warnings,
                );
            }
        }
        return $result;
    }

    /**
     * Checks whether an extracted attribute carries a tag with the given name.
     *
     * @param array $attribute  Attribute array as produced by extractAttributes().
     * @param string $tagName   Tag name to look for (case-insensitive exact match).
     * @return bool             True if the tag is present, false otherwise.
     */
    protected function __attributeHasTag(array $attribute, string $tagName): bool
    {
        if ($tagName === '') {
            return false;
        }
        $needle = strtolower($tagName);
        foreach (['Tag', '_allTags'] as $key) {
            if (!empty($attribute[$key]) && is_array($attribute[$key])) {
                foreach ($attribute[$key] as $tag) {
                    if (isset($tag['name']) && strtolower($tag['name']) === $needle) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Sends a notification toast in the MISP UI.
     */
    protected function __notification(string $message, string $variant, WorkflowRoamingData $roamingData): bool
    {
        $user = $roamingData->getInitiatorUser();
        $userSource = 'initiator';
        if (empty($user['User']['id'])) {
            $user = $roamingData->getUser();
            $userSource = 'workflow-user';
            // getUser() returns a flat user array; createNotificationToast wants the ['User' => ...] envelope.
            if (!empty($user) && !isset($user['User'])) {
                $user = ['User' => $user];
            }
        }
        $ok = false;
        if (!empty($user['User']['id'])) {
            $ok = (bool)$this->User->createNotificationToast($user, $this->name, $message, $variant);
        }
        $this->__log(sprintf(
            'toast: ok=%s user=%s(%s) variant=%s msg=%s',
            $ok ? 'true' : 'false',
            $userSource,
            $user['User']['id'] ?? 'unknown',
            $variant,
            $message
        ));
        return $ok;
    }

    /**
     * Records an error, logs it, sends a danger toast and returns false.
     */
    protected function __fail(string $message, array &$errors, WorkflowRoamingData $roamingData): bool
    {
        $errors[] = $message;
        $this->__log($message);
        $this->__notification($message, 'danger', $roamingData);
        return false;
    }

    /**
     * Writes the blocklist content to a file in the export format.
     *
     * @param string $blocklist           The full path to the blocklist file.
     * @param array $blocklistContent     The list of entries to write to the blocklist.
     * @return bool True on success, false on failure.
     */
    protected function __writeBlocklist(string $blocklist, array $blocklistContent): bool
    {
        $lines = [];
        foreach ($blocklistContent as $entry) {
            $entry = $this->__transformValue($entry);
            if ($entry === '') {
                continue;
            }
            if ($this->exportFormat === 'regex') {
                $lines[] = '*' . $entry . '*';
            } elseif ($this->exportFormat === 'paloalto') {
                $line = '*' . $entry;
                if (strlen($line) > 255) {
                    $line = substr($line, 0, 255);
                }
                $lines[] = $line;
            } elseif ($this->exportFormat === 'firewall') {
                $lines[] = $entry;
            } else {
                $this->__log('Unsupported export format: ' . $this->exportFormat);
                return false;
            }
        }
        if ($this->exportFormat === 'regex') {
            array_unshift($lines, 'type=regex');
        }
        $output = implode(PHP_EOL, $lines) . PHP_EOL;

        $lockPath = $blocklist . '.lock';
        $lockHandle = @fopen($lockPath, 'c');
        if ($lockHandle === false) {
            $this->__log('Failed to open lock file: ' . $lockPath);
            return false;
        }
        if (!flock($lockHandle, LOCK_EX)) {
            fclose($lockHandle);
            $this->__log('Failed to acquire lock on: ' . $lockPath);
            return false;
        }

        try {
            // Best-effort one-generation backup of the current file.
            if (file_exists($blocklist)) {
                if (!@copy($blocklist, $blocklist . '.previous')) {
                    $this->__log('Failed to rotate blocklist to .previous: ' . $blocklist . '.previous');
                }
            }

            $tmp = $blocklist . '.tmp';
            if (file_put_contents($tmp, $output) === false) {
                $this->__log('Failed to write temp blocklist file: ' . $tmp);
                return false;
            }
            if (file_exists($blocklist)) {
                $perms = @fileperms($blocklist);
                if ($perms !== false) {
                    @chmod($tmp, $perms & 0777);
                }
            }
            if (!@rename($tmp, $blocklist)) {
                $this->__log('Failed to rename temp blocklist into place: ' . $tmp . ' -> ' . $blocklist);
                @unlink($tmp);
                return false;
            }
            return true;
        } finally {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
    }

    /**
     * Reads and parses the blocklist file according to the export format.
     *
     * @param string $blocklist   The full path to the blocklist file.
     * @return array              The cleaned list of blocklist entries.
     */
    protected function __readBlocklist(string $blocklist): array
    {
        if (!is_readable($blocklist)) {
            return [];
        }

        $blocklistContent = file($blocklist, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($blocklistContent)) {
            return [];
        }

        $cleaned = [];

        foreach ($blocklistContent as $line) {
            $line = trim($line);
            if ($this->exportFormat === 'regex') {
                if (strtolower($line) === 'type=regex') {
                    continue;
                }
                // Lines were written as: *<value>*
                if (preg_match('/^\*(.*)\*$/', $line, $m)) {
                    $line = $m[1];
                }
            } elseif ($this->exportFormat === 'paloalto') {
                // Written as: *<value> (possibly truncated to 255 chars)
                $line = ltrim($line, '*');
            }
            // 'firewall' format is stored verbatim, nothing to strip.
            if ($line !== '') {
                $cleaned[] = $line;
            }
        }
        return $cleaned;
    }

    /**
     * Logs a message to the workflow execution log file if debug logging is enabled.
     *
     * @param mixed $message   The message or array to log.
     * @param bool $var_dump   If true, use var_dump for output; otherwise use print_r for arrays.
     * @return bool            True if the log was written, false otherwise.
     */
    protected function __log($message, bool $var_dump = false): bool
    {
        if ($this->debugLog) {
            if (is_array($message) && !$var_dump) {
                $message = print_r($message, true);
            } elseif ($var_dump) {
                ob_start();
                var_dump($message);
                $message = ob_get_clean();
            }
            $logEntry = PHP_EOL . '[' . date('Y-m-d H:i:s') . '] ' . $message . PHP_EOL;
            FileAccessTool::writeToFile(APP . 'tmp/logs/workflow-execution.log', $logEntry, false, true);
            return true;
        }
        return false;
    }
}

