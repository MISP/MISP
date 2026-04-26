<?php
App::uses('EventTemplateDependencies', 'Tools');
App::uses('EventTemplateValidator', 'Tools');
App::uses('EventTemplateInfoRenderer', 'Tools');
App::uses('EventTemplateInstantiationException', 'Tools');
App::uses('ClassRegistry', 'Utility');

/**
 * Takes an event-template definition + user-submitted field values and
 * creates a fully-populated MISP event (attributes, MISP objects, object
 * references, event-level tags, synthetic galaxy-cluster tags) inside a
 * single transaction. Rolls back atomically on any failure.
 *
 * See PRD §§5.2 F2.8-F2.10 for the contract.
 *
 * Entry point:
 *   instantiate(array $definition, array $userInput, array $user, array $options = [])
 *     -> ['event_id' => int, 'event_uuid' => string]
 *
 * $userInput keys are element ids from the template's structure. For
 * attribute/tag/galaxy fields the value is either a string or an array of
 * strings (repeatable). For object_field elements the value is either a
 * map {relation => value} or an array of such maps (repeatable). Example:
 *
 *   [
 *     'sender'          => 'attacker@evil.example',     // attribute_field
 *     'tags_campaign'   => ['tlp:amber'],               // tag_field (multi)
 *     'gal_actor'       => 'APT28',                     // galaxy_field
 *     'obj_email'       => [
 *         'from'    => 'attacker@evil.example',
 *         'subject' => 'ur pwned',
 *     ],
 *     'obj_attachment'  => [                             // repeatable
 *         ['filename' => 'a.exe', 'sha256' => '...'],
 *         ['filename' => 'b.exe', 'sha256' => '...'],
 *     ],
 *   ]
 *
 * file_field elements accept arrays of {filename, data_base64}
 * (data is the raw file content base64-encoded on the client).
 * Each instance becomes an `attachment` or `malware-sample` attribute
 * depending on the template's `as` choice; malware-samples flow
 * through MISP's onDemandEncrypt hook for the zipped/encrypted
 * filename|md5 composite.
 *
 * Repeatable object_references: if either endpoint is repeatable and
 * appears more than once, the reference is materialised between the
 * first instance of each side only. Additional references can be
 * declared explicitly by adding more object_reference elements.
 */
class EventTemplateInstantiator
{
    /** @var array<string,array> key "uuid@version" -> {meta_category, relations} (lazy) */
    private $objectTemplateSpec = array();

    /**
     * @param array $definition template definition (decoded JSON)
     * @param array $userInput  map: element id -> value | array of values
     * @param array $user       CakePHP Auth user shape (id, org_id, Role[], ...)
     * @param array $options    optional context for the call. Recognised keys:
     *                          - 'template' => ['id', 'uuid', 'version', 'name']
     *                            When present, an `instantiate` audit-log row
     *                            is written post-commit linking the new event
     *                            back to the source template (PRD §5.3 F3.4).
     *                            Omitting it skips the audit row — useful for
     *                            tests or anonymous programmatic uses.
     * @return array ['event_id' => int, 'event_uuid' => string]
     * @throws EventTemplateInstantiationException
     * @throws EventTemplateDependencyMissingException
     */
    public function instantiate(array $definition, array $userInput, array $user, array $options = array())
    {
        EventTemplateDependencies::requireAll();

        $validator = new EventTemplateValidator();
        $errs = $validator->validate($definition);
        if (!empty($errs)) {
            throw new EventTemplateInstantiationException(
                'Template definition is invalid; refusing to instantiate.',
                $errs
            );
        }

        $errs = $this->validateUserInput($definition, $userInput);
        if (!empty($errs)) {
            throw new EventTemplateInstantiationException('User input is invalid.', $errs);
        }

        $eventData = $this->buildEventArray($definition, $userInput, $user);

        $eventModel = ClassRegistry::init('Event');
        $db = $eventModel->getDataSource();
        $transactionBegun = $db->begin();

        try {
            $created_id = 0;
            $validationErrors = array();
            $result = $eventModel->_add(
                $eventData,
                false,
                $user,
                0,
                null,
                false,
                null,
                $created_id,
                $validationErrors,
                false
            );

            if ($result !== true) {
                if ($transactionBegun) {
                    $db->rollback();
                }
                throw new EventTemplateInstantiationException(
                    'Event creation failed.',
                    $this->normaliseAddFailure($result, $validationErrors)
                );
            }

            // _add's &$created_id isn't reliably populated in all code paths;
            // fall back to $eventModel->id, which the underlying save() sets.
            $newId = ((int)$created_id > 0) ? (int)$created_id : (int)$eventModel->id;
            if ($newId <= 0) {
                if ($transactionBegun) {
                    $db->rollback();
                }
                throw new EventTemplateInstantiationException(
                    'Event creation appeared to succeed but no id was returned.',
                    array('Event::_add returned true but neither $created_id nor $eventModel->id was populated')
                );
            }

            // _add logs "dropped" attributes/objects on validation errors and
            // still returns true. Verify counts match what we submitted; if
            // anything went missing, roll back and surface the drops.
            $dropErrors = $this->verifyEventContents($eventModel, $newId, $eventData['Event']);
            if (!empty($dropErrors)) {
                if ($transactionBegun) {
                    $db->rollback();
                }
                throw new EventTemplateInstantiationException(
                    'Some attributes or objects were dropped during event creation.',
                    $dropErrors
                );
            }

            // Attach event-level tags (defaults + synthesised galaxy tags +
            // user-picked tag/galaxy fields) via the canonical helper. Doing
            // this here rather than via a nested array in $eventData is
            // deliberate — _add()'s handling of nested tag arrays is
            // inconsistent, and the helper is the same path the event UI
            // uses. Still inside our transaction.
            $tagNames = $this->collectEventTagNames($definition, $userInput);
            if (!empty($tagNames)) {
                $tagAttached = array();
                $eventModel->attachTagsToEventAndTouch(
                    $newId,
                    array(
                        'tags' => $tagNames,
                        'local' => 0,
                        'relationship_type' => null,
                    ),
                    $user,
                    $tagAttached
                );
            }

            if ($transactionBegun) {
                $db->commit();
            }

            $eventRow = $eventModel->find('first', array(
                'conditions' => array('Event.id' => $newId),
                'recursive' => -1,
                'fields' => array('Event.id', 'Event.uuid'),
            ));
            $eventUuid = isset($eventRow['Event']['uuid']) ? $eventRow['Event']['uuid'] : '';

            $autoLinkMap = $this->buildAutoLinkMap($definition, $userInput, $newId);
            $this->saveEventReports($definition, $userInput, $user, $newId, $autoLinkMap);
            $this->writeInstantiationSummaryReport(
                $newId, (string)$eventUuid, $definition, $userInput, $user, $options, $autoLinkMap
            );
            $this->writeInstantiationAuditRow($newId, (string)$eventUuid, $options);

            return array(
                'event_id' => $newId,
                'event_uuid' => (string)$eventUuid,
            );
        } catch (EventTemplateInstantiationException $e) {
            throw $e;
        } catch (Throwable $e) {
            // Throwable rather than Exception so PHP 7+ TypeError / Error
            // subclasses also trigger rollback.
            if ($transactionBegun) {
                $db->rollback();
            }
            throw $e;
        }
    }

    // --- Event reports ------------------------------------------------------

    /**
     * Saves an EventReport row for each `event_report` element in the
     * template whose user input is non-empty. Runs post-commit because
     * EventReport.event_id references the just-saved event row; a save
     * failure is logged as a warning but does not roll back the event
     * (mirrors the audit-row pattern — the event is already on disk).
     *
     * `$autoLinkMap` (from buildAutoLinkMap) is applied to each report's
     * content before save so attribute / tag / galaxy references in the
     * user's prose render as proper EventReport links.
     */
    private function saveEventReports(array $definition, array $userInput, array $user, $eventId, array $autoLinkMap = array())
    {
        $structure = isset($definition['structure']) && is_array($definition['structure'])
            ? $definition['structure']
            : array();
        $reports = array();
        foreach ($structure as $el) {
            if (!is_array($el) || ($el['type'] ?? null) !== 'event_report') {
                continue;
            }
            $id = $el['id'] ?? '';
            if ($id === '' || !isset($userInput[$id])) {
                continue;
            }
            $content = $userInput[$id];
            if (!is_string($content) || trim($content) === '') {
                continue;
            }
            $reports[] = array(
                'name' => isset($el['label']) ? (string)$el['label'] : $id,
                'content' => $this->applyAutoLinks($content, $autoLinkMap),
                'distribution' => 5,
                'event_id' => (int)$eventId,
            );
        }
        if (empty($reports)) {
            return;
        }
        try {
            $eventReport = ClassRegistry::init('EventReport');
            foreach ($reports as $report) {
                $errs = $eventReport->addReport($user, $report, (int)$eventId);
                if (!empty($errs)) {
                    CakeLog::warning(
                        'EventTemplateInstantiator: event_report save returned errors '
                        . 'for event_id=' . (int)$eventId . ': '
                        . json_encode($errs)
                    );
                }
            }
        } catch (Throwable $e) {
            CakeLog::warning(
                'EventTemplateInstantiator: failed to save event_report rows '
                . 'for event_id=' . (int)$eventId . ': ' . $e->getMessage()
            );
        }
    }

    /**
     * Writes a system-generated EventReport summarising the instantiation
     * call: which template was used, by whom, and the field-by-field
     * choices. Useful audit trail for the resulting event.
     *
     * Gated on `$options['template']` for the same reason as the audit
     * row — without template metadata we have no name/uuid/version to
     * reference. Save failures are logged as warnings rather than rolling
     * back the freshly-committed event (mirrors the audit-row pattern).
     *
     * `event_report` elements are skipped — they are already attached as
     * their own EventReport rows by saveEventReports(). Section,
     * text_block, and object_reference elements have no user input so
     * they're skipped too.
     *
     * v1 always emits the report. If it gets noisy, the natural follow-up
     * is a config flag (e.g. MISP.event_template_instantiation_summary)
     * gating the call.
     */
    private function writeInstantiationSummaryReport(
        $eventId, $eventUuid, array $definition, array $userInput, array $user, array $options, array $autoLinkMap = array()
    ) {
        if (empty($options['template']) || !is_array($options['template'])) {
            return;
        }
        $tpl = $options['template'];
        $name = isset($tpl['name']) ? (string)$tpl['name'] : '(unknown)';
        $uuid = isset($tpl['uuid']) ? (string)$tpl['uuid'] : '';
        $version = isset($tpl['version']) ? (int)$tpl['version'] : 0;
        $userEmail = isset($user['email']) ? (string)$user['email'] : '(unknown)';
        $isoTime = gmdate('c');

        $structure = isset($definition['structure']) && is_array($definition['structure'])
            ? $definition['structure']
            : array();
        $skipTypes = array('section', 'text_block', 'object_reference', 'event_report');
        $bullets = array();
        foreach ($structure as $el) {
            if (!is_array($el) || !isset($el['type'], $el['id'])) {
                continue;
            }
            if (in_array($el['type'], $skipTypes, true)) {
                continue;
            }
            $id = $el['id'];
            if (!isset($userInput[$id]) || $this->isEmptyValue($userInput[$id])) {
                continue;
            }
            $label = isset($el['label']) ? (string)$el['label'] : $id;
            $rendered = $this->renderUserValueForSummary($el['type'], $userInput[$id]);
            if ($rendered === '') {
                continue;
            }
            $bullets[] = sprintf('- **%s**: %s', $label, $rendered);
        }

        $body = sprintf(
            "This event was created from event template **%s** (uuid `%s`, version %d) by %s on %s.\n\n## Filled values\n\n",
            $name, $uuid, $version, $userEmail, $isoTime
        );
        $body .= empty($bullets)
            ? "_(no fields were filled)_\n"
            : implode("\n", $bullets) . "\n";

        // Apply auto-link substitutions so attribute / tag / galaxy values
        // in the bullets render as report links rather than literal text.
        $body = $this->applyAutoLinks($body, $autoLinkMap);

        $reportName = sprintf('Instantiation report — %s v%d', $name, $version);

        try {
            $eventReport = ClassRegistry::init('EventReport');
            $errs = $eventReport->addReport($user, array(
                'name' => $reportName,
                'content' => $body,
                'distribution' => 5,
                'event_id' => (int)$eventId,
            ), (int)$eventId);
            if (!empty($errs)) {
                CakeLog::warning(
                    'EventTemplateInstantiator: instantiation summary report save '
                    . 'returned errors for event_id=' . (int)$eventId . ': '
                    . json_encode($errs)
                );
            }
        } catch (Throwable $e) {
            CakeLog::warning(
                'EventTemplateInstantiator: failed to save instantiation summary '
                . 'report for event_id=' . (int)$eventId . ': ' . $e->getMessage()
            );
        }
    }

    /**
     * Renders the user's value for one element into an inline-Markdown
     * fragment for the instantiation summary. Output is single-line for
     * scalar inputs (attribute / tag / galaxy fields, single object
     * fields, file fields) and multi-line with sub-bullets for repeatable
     * object fields with more than one instance.
     */
    private function renderUserValueForSummary($type, $value)
    {
        if ($type === 'file_field') {
            $names = array();
            foreach ($this->normaliseFileInstances($value) as $inst) {
                if (is_array($inst) && !empty($inst['filename'])) {
                    $names[] = '`' . str_replace('`', '', (string)$inst['filename']) . '`';
                }
            }
            return implode(', ', $names);
        }
        if ($type === 'object_field') {
            $instances = $this->normaliseObjectInstances($value);
            $instances = array_values(array_filter($instances, function ($inst) {
                return is_array($inst) && !empty($inst);
            }));
            if (count($instances) === 0) {
                return '';
            }
            if (count($instances) === 1) {
                return $this->renderRelationMapForSummary($instances[0]);
            }
            $lines = array();
            foreach ($instances as $idx => $inst) {
                $line = $this->renderRelationMapForSummary($inst);
                if ($line !== '') {
                    $lines[] = sprintf("\n    - instance %d: %s", $idx + 1, $line);
                }
            }
            return implode('', $lines);
        }
        // attribute_field, tag_field, galaxy_field — scalar or list of strings.
        if (is_array($value)) {
            $items = array();
            foreach ($value as $v) {
                $s = $this->summariseScalarValue($v);
                if ($s !== '') {
                    $items[] = $s;
                }
            }
            return implode(', ', $items);
        }
        return $this->summariseScalarValue($value);
    }

    private function renderRelationMapForSummary(array $map)
    {
        $pairs = array();
        foreach ($map as $rel => $v) {
            $s = $this->summariseScalarValue($v);
            if ($s !== '') {
                $pairs[] = sprintf('%s=%s', (string)$rel, $s);
            }
        }
        return implode(', ', $pairs);
    }

    private function summariseScalarValue($v)
    {
        if ($v === null || !is_scalar($v)) {
            return '';
        }
        $s = trim((string)$v);
        if ($s === '') {
            return '';
        }
        // Single-line: collapse internal whitespace runs. No inline-code
        // wrapping — bare scalars let auto-link substitutions render as
        // proper @[attribute]/@[tag] links instead of literal code spans.
        return preg_replace('/\s+/', ' ', $s);
    }

    // --- Auto-link enrichment ---------------------------------------------

    /**
     * Builds a value→marker map for cross-linking just-saved entities
     * inside EventReport content. Three sources, in priority order:
     *
     *   1. Attribute uuids — queried from the event row by event_id.
     *      Marker: @[attribute](<uuid>). Catches any attribute whose
     *      value (length >= 3) appears verbatim in the report prose.
     *
     *   2. tag_field user input — link by raw tag name.
     *      Marker: @[tag](<name>).
     *
     *   3. galaxy_field user input — link by raw value, but the marker
     *      uses the synthesised tag_name (`misp-galaxy:<type>="<value>"`)
     *      since that is what is actually attached to the event.
     *
     * Object references and synonym matches are deferred to v2 — there
     * is no clean value-to-marker mapping for misp-objects (the user
     * never sees the object's uuid in their input), and the broad
     * synonym scan that EventReport::extractWithReplacements does walks
     * every galaxy cluster in the DB, which would dominate
     * instantiation latency.
     */
    private function buildAutoLinkMap(array $definition, array $userInput, $eventId)
    {
        $map = array();
        $structure = isset($definition['structure']) && is_array($definition['structure'])
            ? $definition['structure']
            : array();

        $attributeModel = ClassRegistry::init('Attribute');
        $rows = $attributeModel->find('all', array(
            'conditions' => array(
                'Attribute.event_id' => (int)$eventId,
                'Attribute.deleted' => 0,
            ),
            'fields' => array('Attribute.uuid', 'Attribute.value'),
            'recursive' => -1,
        ));
        foreach ($rows as $r) {
            $val = isset($r['Attribute']['value']) ? (string)$r['Attribute']['value'] : '';
            $uuid = isset($r['Attribute']['uuid']) ? (string)$r['Attribute']['uuid'] : '';
            if (strlen($val) >= 3 && $uuid !== '' && !isset($map[$val])) {
                $map[$val] = sprintf('@[attribute](%s)', $uuid);
            }
        }

        foreach ($structure as $el) {
            if (!is_array($el) || !isset($el['type'], $el['id'])) {
                continue;
            }
            $type = $el['type'];
            if ($type !== 'tag_field' && $type !== 'galaxy_field') {
                continue;
            }
            $id = $el['id'];
            if (!isset($userInput[$id])) {
                continue;
            }
            $values = is_array($userInput[$id]) ? $userInput[$id] : array($userInput[$id]);
            $galaxyType = null;
            if ($type === 'galaxy_field') {
                $restrict = isset($el['restrict_galaxy_types']) && is_array($el['restrict_galaxy_types'])
                    ? $el['restrict_galaxy_types']
                    : array();
                $galaxyType = $restrict ? (string)reset($restrict) : 'unknown';
            }
            foreach ($values as $v) {
                if (!is_string($v)) {
                    continue;
                }
                $v = trim($v);
                if (strlen($v) < 3 || isset($map[$v])) {
                    continue;
                }
                if ($type === 'tag_field') {
                    $map[$v] = sprintf('@[tag](%s)', $v);
                } else {
                    $map[$v] = sprintf('@[tag](misp-galaxy:%s="%s")', $galaxyType, $v);
                }
            }
        }

        // Sort by descending key length so longer matches replace before
        // shorter substrings that might overlap (e.g. "8.8.4.4" before
        // any 3-char prefix).
        uksort($map, function ($a, $b) {
            return strlen($b) - strlen($a);
        });

        return $map;
    }

    /**
     * Applies a value→marker substitution map to a Markdown content
     * string. Word-boundary aware: a 3-char value like "npm" should
     * link "the npm package" but NOT the "npm" substring inside
     * ".npmrc". Boundaries are only emitted at edges where the value
     * starts/ends with a word character — URL values ending in "/"
     * don't get a trailing boundary, otherwise they wouldn't match
     * before whitespace (a non-word/non-word boundary doesn't fire).
     */
    private function applyAutoLinks($content, array $map)
    {
        if (!is_string($content) || $content === '' || empty($map)) {
            return $content;
        }
        foreach ($map as $needle => $marker) {
            $leading = preg_match('/^\w/', $needle) ? '\b' : '';
            $trailing = preg_match('/\w$/', $needle) ? '\b' : '';
            $pattern = '/' . $leading . preg_quote($needle, '/') . $trailing . '/';
            // Replacement strings in preg_replace treat \ and $ specially
            // (back-references). Escape them so a tag value like 'foo$1'
            // doesn't confuse the regex engine.
            $replacement = addcslashes($marker, '\\$');
            $replaced = preg_replace($pattern, $replacement, $content);
            if ($replaced !== null) {
                $content = $replaced;
            }
        }
        return $content;
    }

    // --- Audit log ----------------------------------------------------------

    /**
     * Writes an `instantiate` audit-log row tying the freshly-created event
     * back to the source template (PRD §5.3 F3.4). Skipped silently if the
     * caller did not pass `$options['template']` — useful for tests and
     * programmatic uses outside the controller.
     *
     * Audit failures must not affect the successfully-committed event, so
     * any exception from the AuditLog model is swallowed and demoted to
     * a CakeLog warning. The event row is already on disk by this point.
     */
    private function writeInstantiationAuditRow($eventId, $eventUuid, array $options)
    {
        if (empty($options['template']) || !is_array($options['template'])) {
            return;
        }
        $tpl = $options['template'];
        try {
            App::uses('AuditLog', 'Model');
            $auditLog = ClassRegistry::init('AuditLog');
            $auditLog->insert(array(
                'action' => AuditLog::ACTION_INSTANTIATE,
                'model' => 'EventTemplate',
                'model_id' => isset($tpl['id']) ? (int)$tpl['id'] : 0,
                'model_title' => isset($tpl['name']) ? (string)$tpl['name'] : '',
                'event_id' => (int)$eventId,
                'change' => array(
                    'event_template_id'      => isset($tpl['id'])      ? (int)$tpl['id']         : 0,
                    'event_template_uuid'    => isset($tpl['uuid'])    ? (string)$tpl['uuid']    : '',
                    'event_template_version' => isset($tpl['version']) ? (int)$tpl['version']    : 0,
                    'event_template_name'    => isset($tpl['name'])    ? (string)$tpl['name']    : '',
                    'event_uuid'             => (string)$eventUuid,
                ),
            ));
        } catch (Throwable $e) {
            CakeLog::warning(
                'EventTemplateInstantiator: failed to write instantiation '
                . 'audit row for event_id=' . (int)$eventId . ': '
                . $e->getMessage()
            );
        }
    }

    // --- Validation ---------------------------------------------------------

    private function validateUserInput(array $definition, array $userInput)
    {
        $errors = array();
        $elements = isset($definition['structure']) && is_array($definition['structure'])
            ? $definition['structure']
            : array();

        $interactiveIds = array();
        foreach ($elements as $el) {
            if (!is_array($el) || !isset($el['type'], $el['id'])) {
                continue;
            }
            $t = $el['type'];
            if ($t === 'section' || $t === 'text_block' || $t === 'object_reference') {
                continue;
            }
            $interactiveIds[$el['id']] = $el;
        }

        // file_field inputs must be {filename, data} objects (base64
        // `data`) or arrays of them when the field is repeatable. An
        // inline stub that still looks like a string — e.g., the user
        // accidentally typed into a stale text control — must be
        // rejected with a clear message rather than silently skipped.
        foreach ($interactiveIds as $id => $el) {
            if ($el['type'] !== 'file_field' || !isset($userInput[$id])) {
                continue;
            }
            if (empty($userInput[$id])) {
                continue;
            }
            foreach ($this->normaliseFileInstances($userInput[$id]) as $idx => $inst) {
                if (!is_array($inst)
                    || !isset($inst['filename']) || !is_string($inst['filename'])
                    || $inst['filename'] === ''
                ) {
                    $errors[] = sprintf(
                        'file_field "%s" instance %d: missing or empty filename',
                        $id, $idx + 1
                    );
                    continue;
                }
                if (!isset($inst['data']) || !is_string($inst['data']) || $inst['data'] === '') {
                    $errors[] = sprintf(
                        'file_field "%s" instance %d: missing base64 data',
                        $id, $idx + 1
                    );
                    continue;
                }
                if (base64_decode($inst['data'], true) === false) {
                    $errors[] = sprintf(
                        'file_field "%s" instance %d: data is not valid base64',
                        $id, $idx + 1
                    );
                }
            }
        }

        // event_report inputs must be plain strings (Markdown body of the
        // report). Reject array shapes so a stale form widget doesn't slip
        // through unnoticed.
        foreach ($interactiveIds as $id => $el) {
            if ($el['type'] !== 'event_report' || !isset($userInput[$id])) {
                continue;
            }
            if ($userInput[$id] !== null && !is_string($userInput[$id])) {
                $errors[] = sprintf(
                    'event_report "%s": expected string, got %s',
                    $id, gettype($userInput[$id])
                );
            }
        }

        // Reject unknown ids.
        foreach (array_keys($userInput) as $id) {
            if (!isset($interactiveIds[$id])) {
                $errors[] = sprintf('unknown field id in user input: %s', $id);
            }
        }

        // Check mandatory fields.
        foreach ($interactiveIds as $id => $el) {
            $isMandatory = !empty($el['mandatory']);
            if (!$isMandatory) {
                continue;
            }
            if (!isset($userInput[$id]) || $this->isEmptyValue($userInput[$id])) {
                $errors[] = sprintf('mandatory field "%s" is empty', $id);
                continue;
            }
            // For object_field with mandatory relations, check each instance's
            // relations that are themselves marked mandatory have a value.
            if ($el['type'] === 'object_field') {
                $mandatoryRelations = array();
                if (isset($el['relations']) && is_array($el['relations'])) {
                    foreach ($el['relations'] as $rel) {
                        if (!empty($rel['mandatory']) && isset($rel['object_relation'])) {
                            $mandatoryRelations[] = $rel['object_relation'];
                        }
                    }
                }
                foreach ($this->normaliseObjectInstances($userInput[$id]) as $idx => $instance) {
                    foreach ($mandatoryRelations as $rel) {
                        if (!isset($instance[$rel]) || $this->isEmptyValue($instance[$rel])) {
                            $errors[] = sprintf(
                                'object_field "%s" instance %d: mandatory relation "%s" is empty',
                                $id, $idx + 1, $rel
                            );
                        }
                    }
                }
            }
        }

        return $errors;
    }

    private function isEmptyValue($v)
    {
        if ($v === null) {
            return true;
        }
        if (is_string($v)) {
            return trim($v) === '';
        }
        if (is_array($v)) {
            if (count($v) === 0) {
                return true;
            }
            foreach ($v as $item) {
                if (!$this->isEmptyValue($item)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    // --- Event-array construction ------------------------------------------

    private function buildEventArray(array $definition, array $userInput, array $user)
    {
        $defaults = isset($definition['event_defaults']) && is_array($definition['event_defaults'])
            ? $definition['event_defaults']
            : array();

        $event = array(
            'published' => 0,
            'info' => $this->renderInfo($defaults, $userInput, $user),
            'distribution' => isset($defaults['distribution']) ? (int)$defaults['distribution'] : 0,
            'threat_level_id' => isset($defaults['threat_level_id']) ? (int)$defaults['threat_level_id'] : 4,
            'analysis' => isset($defaults['analysis']) ? (int)$defaults['analysis'] : 0,
        );
        if (isset($defaults['sharing_group_id']) && $defaults['sharing_group_id'] !== null) {
            $event['sharing_group_id'] = (int)$defaults['sharing_group_id'];
        }

        $event['Attribute'] = $this->buildAttributes($definition, $userInput);
        $event['Object']    = $this->buildObjects($definition, $userInput);
        // Tags are attached post-_add via Event::attachTagsToEventAndTouch()
        // because _add()'s handling of nested tag arrays is inconsistent
        // (silently drops them when the shape is not exactly what it expects).

        return array('Event' => $event);
    }

    private function renderInfo(array $defaults, array $userInput, array $user)
    {
        $template = isset($defaults['info_template']) && is_string($defaults['info_template'])
            ? $defaults['info_template']
            : '';
        if ($template === '') {
            return 'Event from template';
        }
        $context = array();
        if (isset($user['email'])) {
            $context['user'] = (string)$user['email'];
        }
        $flat = $this->flattenFieldValuesForInfoTemplate($userInput);
        $renderer = new EventTemplateInfoRenderer();
        return $renderer->render($template, $flat, $context);
    }

    /**
     * For info_template {{field:<id>}} references: attribute/tag/galaxy
     * fields resolve to their scalar value or array-of-strings; object
     * fields resolve to the first instance's string representation (not
     * useful for info templates, but we do not crash).
     */
    private function flattenFieldValuesForInfoTemplate(array $userInput)
    {
        $out = array();
        foreach ($userInput as $id => $v) {
            if (is_array($v)) {
                // For repeatable attribute/tag/galaxy input, $v is list<string>;
                // for object input, it's a map or list<map>. Info templates
                // only really make sense with scalar/list<scalar>; in the
                // object case we skip silently.
                $first = reset($v);
                if (is_string($first) || $first === null) {
                    $out[$id] = $v;
                    continue;
                }
                // Object input — no scalar projection.
                continue;
            }
            $out[$id] = $v;
        }
        return $out;
    }

    private function buildAttributes(array $definition, array $userInput)
    {
        $attrs = array();
        foreach ($definition['structure'] as $el) {
            if (!is_array($el) || !isset($el['type'], $el['id'])) {
                continue;
            }
            $id = $el['id'];
            if (!isset($userInput[$id]) || $this->isEmptyValue($userInput[$id])) {
                continue;
            }

            if ($el['type'] === 'attribute_field') {
                $misp = isset($el['misp']) && is_array($el['misp']) ? $el['misp'] : array();
                $category = isset($misp['category']) ? (string)$misp['category'] : '';
                $type = isset($misp['type']) ? (string)$misp['type'] : '';
                $toIds = isset($misp['to_ids_default']) ? (bool)$misp['to_ids_default'] : true;
                $comment = isset($misp['comment_template']) ? (string)$misp['comment_template'] : '';

                foreach ($this->normaliseScalarInstances($userInput[$id]) as $value) {
                    $attrs[] = array(
                        'category' => $category,
                        'type' => $type,
                        'value' => (string)$value,
                        'to_ids' => $toIds ? 1 : 0,
                        'comment' => $comment,
                        'distribution' => 5,
                    );
                }
                continue;
            }

            if ($el['type'] === 'file_field') {
                $as = isset($el['as']) && $el['as'] === 'malware-sample'
                    ? 'malware-sample'
                    : 'attachment';
                foreach ($this->normaliseFileInstances($userInput[$id]) as $inst) {
                    if (!is_array($inst)
                        || empty($inst['filename']) || empty($inst['data'])
                    ) {
                        continue; // guarded by validateUserInput already
                    }
                    $attr = array(
                        'category' => 'Payload delivery',
                        'type' => $as,
                        'value' => (string)$inst['filename'],
                        'to_ids' => $as === 'malware-sample' ? 1 : 0,
                        'comment' => '',
                        'distribution' => 5,
                        'data' => (string)$inst['data'],
                    );
                    if ($as === 'malware-sample') {
                        // Event::_add -> Attribute handling picks this up
                        // and routes through onDemandEncrypt to produce
                        // the zipped/encrypted sample + filename|md5
                        // composite value.
                        $attr['encrypt'] = true;
                    }
                    $attrs[] = $attr;
                }
                continue;
            }
        }
        return $attrs;
    }

    /**
     * Normalises a file_field user-input payload into a list of
     * {filename, data} associative arrays. Accepts either a single
     * instance ({"filename": ..., "data": ...}) or a list of them.
     */
    private function normaliseFileInstances($v)
    {
        if (is_array($v) && isset($v['filename'])) {
            return array($v);
        }
        if (is_array($v)) {
            return array_values($v);
        }
        return array();
    }

    private function buildObjects(array $definition, array $userInput)
    {
        $objects = array();
        $objectInstances = array();  // id -> list of saved objects (for reference resolution)

        foreach ($definition['structure'] as $el) {
            if (!is_array($el) || !isset($el['type'], $el['id']) || $el['type'] !== 'object_field') {
                continue;
            }
            $id = $el['id'];
            if (!isset($userInput[$id]) || $this->isEmptyValue($userInput[$id])) {
                continue;
            }

            $ot = isset($el['object_template']) && is_array($el['object_template'])
                ? $el['object_template']
                : array();
            $otUuid = isset($ot['uuid']) ? (string)$ot['uuid'] : '';
            $otName = isset($ot['name']) ? (string)$ot['name'] : '';
            $otVersion = isset($ot['minimum_version']) ? (int)$ot['minimum_version'] : 1;

            $spec = $this->loadObjectTemplateSpec($otUuid, $otVersion);
            $relationMap = $spec['relations'];

            $objectInstances[$id] = array();
            foreach ($this->normaliseObjectInstances($userInput[$id]) as $instance) {
                $objectUuid = $this->generateUuid();
                $nestedAttrs = array();
                foreach ($instance as $relationName => $relValue) {
                    if ($this->isEmptyValue($relValue)) {
                        continue;
                    }
                    if (!isset($relationMap[$relationName])) {
                        continue;
                    }
                    $def = $relationMap[$relationName];
                    foreach ($this->normaliseScalarInstances($relValue) as $v) {
                        $nestedAttrs[] = array(
                            'object_relation' => $relationName,
                            'type' => $def['type'],
                            'category' => $def['category'],
                            'value' => (string)$v,
                            'to_ids' => $def['to_ids'] ? 1 : 0,
                            'distribution' => 5,
                        );
                    }
                }
                $obj = array(
                    'name' => $otName,
                    'meta-category' => $spec['meta_category'],
                    'description' => $spec['description'],
                    'template_uuid' => $otUuid,
                    // Record the version actually used to build the
                    // object, not the template's pinned minimum. The
                    // minimum_version is a "minimum required" floor; the
                    // matched version is what shaped the relation set
                    // we just persisted (PRD §13).
                    'template_version' => (string)(isset($spec['matched_version']) ? $spec['matched_version'] : $otVersion),
                    'uuid' => $objectUuid,
                    'distribution' => 5,
                    'Attribute' => $nestedAttrs,
                );
                $objectInstances[$id][] = array('uuid' => $objectUuid, 'index' => count($objects));
                $objects[] = $obj;
            }
        }

        // Apply object_reference elements: match first-instance to first-instance.
        foreach ($definition['structure'] as $el) {
            if (!is_array($el) || !isset($el['type']) || $el['type'] !== 'object_reference') {
                continue;
            }
            $from = isset($el['from']) ? $el['from'] : null;
            $to = isset($el['to']) ? $el['to'] : null;
            $relType = isset($el['relationship_type']) ? (string)$el['relationship_type'] : '';
            if ($from === null || $to === null || $relType === '') {
                continue;
            }
            if (empty($objectInstances[$from]) || empty($objectInstances[$to])) {
                // One side was unfilled; skip silently.
                continue;
            }
            $fromInst = $objectInstances[$from][0];
            $toInst = $objectInstances[$to][0];
            if (!isset($objects[$fromInst['index']]['ObjectReference'])) {
                $objects[$fromInst['index']]['ObjectReference'] = array();
            }
            $objects[$fromInst['index']]['ObjectReference'][] = array(
                'source_uuid' => $fromInst['uuid'],
                'referenced_uuid' => $toInst['uuid'],
                'relationship_type' => $relType,
                'comment' => isset($el['comment']) ? (string)$el['comment'] : '',
            );
        }

        return $objects;
    }

    /**
     * Collects every tag name that should be attached to the event:
     *   - event_defaults.tags (plain tag names)
     *   - event_defaults.galaxy_clusters (synthesised as misp-galaxy: tags)
     *   - tag_field user input
     *   - galaxy_field user input (synthesised as misp-galaxy: tags, using
     *     the field's first restrict_galaxy_types entry)
     *
     * Returns a deduplicated list<string>. Attachment happens post-_add()
     * via Event::attachTagsToEventAndTouch().
     */
    private function collectEventTagNames(array $definition, array $userInput)
    {
        $defaults = isset($definition['event_defaults']) && is_array($definition['event_defaults'])
            ? $definition['event_defaults']
            : array();
        $tags = array();

        if (isset($defaults['tags']) && is_array($defaults['tags'])) {
            foreach ($defaults['tags'] as $t) {
                if (is_array($t) && !empty($t['name'])) {
                    $tags[] = (string)$t['name'];
                }
            }
        }
        if (isset($defaults['galaxy_clusters']) && is_array($defaults['galaxy_clusters'])) {
            foreach ($defaults['galaxy_clusters'] as $gc) {
                if (is_array($gc) && isset($gc['galaxy_type'], $gc['value'])) {
                    $tags[] = sprintf(
                        'misp-galaxy:%s="%s"',
                        (string)$gc['galaxy_type'],
                        (string)$gc['value']
                    );
                }
            }
        }
        foreach ($definition['structure'] as $el) {
            if (!is_array($el) || !isset($el['type'], $el['id'])) {
                continue;
            }
            $id = $el['id'];
            if (!isset($userInput[$id]) || $this->isEmptyValue($userInput[$id])) {
                continue;
            }
            if ($el['type'] === 'tag_field') {
                foreach ($this->normaliseScalarInstances($userInput[$id]) as $name) {
                    $tags[] = (string)$name;
                }
            } elseif ($el['type'] === 'galaxy_field') {
                $galaxyTypes = isset($el['restrict_galaxy_types']) && is_array($el['restrict_galaxy_types'])
                    ? $el['restrict_galaxy_types']
                    : array();
                $galaxyType = $galaxyTypes ? (string)reset($galaxyTypes) : 'unknown';
                foreach ($this->normaliseScalarInstances($userInput[$id]) as $val) {
                    $tags[] = sprintf('misp-galaxy:%s="%s"', $galaxyType, (string)$val);
                }
            }
        }
        // Dedupe while preserving order.
        $seen = array();
        $out = array();
        foreach ($tags as $t) {
            if (!isset($seen[$t])) {
                $seen[$t] = true;
                $out[] = $t;
            }
        }
        return $out;
    }

    // --- Helpers ------------------------------------------------------------

    /**
     * Input can be a scalar, or a list of scalars (repeatable). Return a list.
     */
    private function normaliseScalarInstances($v)
    {
        if ($v === null) {
            return array();
        }
        if (is_array($v)) {
            // Filter out empties and non-scalars.
            $out = array();
            foreach ($v as $item) {
                if (!$this->isEmptyValue($item)) {
                    $out[] = $item;
                }
            }
            return $out;
        }
        return array($v);
    }

    /**
     * Object-field input can be a single instance map (assoc array), or a list
     * of instance maps (repeatable). Return a list of maps.
     */
    private function normaliseObjectInstances($v)
    {
        if ($v === null) {
            return array();
        }
        if (!is_array($v)) {
            return array();
        }
        if (empty($v)) {
            return array();
        }
        // Detect "list of maps" vs "single map": a map has at least one non-numeric key.
        $firstKey = array_key_first($v);
        if (is_int($firstKey)) {
            $out = array();
            foreach ($v as $item) {
                if (is_array($item)) {
                    $out[] = $item;
                }
            }
            return $out;
        }
        return array($v);
    }

    /**
     * Loads the object template's meta info + relations, keyed "uuid@version".
     * Returns {meta_category, description, relations:{relation => {type,category,to_ids}}}.
     * MispObject validation requires meta-category on the Object row; we also
     * pull description defensively.
     */
    private function loadObjectTemplateSpec($uuid, $version)
    {
        $cacheKey = strtolower($uuid) . '@' . (int)$version;
        if (isset($this->objectTemplateSpec[$cacheKey])) {
            return $this->objectTemplateSpec[$cacheKey];
        }

        // Treat the template's `minimum_version` as a *minimum*
        // (PRD §13). When the operator's instance carries a newer
        // misp-objects version than the template's pin, instantiation
        // should still work — picks the lowest installed version >=
        // pinned so we use the shape closest to what the template
        // author tested against. Same pattern as the controller's
        // __collectObjectRelationSpecs which renders the user form.
        $ot = ClassRegistry::init('ObjectTemplate')->find('first', array(
            'conditions' => array(
                'ObjectTemplate.uuid' => strtolower((string)$uuid),
                'ObjectTemplate.version >=' => (int)$version,
                'ObjectTemplate.active' => true,
            ),
            'contain' => array('ObjectTemplateElement'),
            'order' => array('ObjectTemplate.version' => 'ASC'),
        ));
        $relations = array();
        $metaCategory = 'misc';
        $description = '';
        $matchedVersion = (int)$version;
        if (!empty($ot)) {
            if (!empty($ot['ObjectTemplate']['meta-category'])) {
                $metaCategory = (string)$ot['ObjectTemplate']['meta-category'];
            }
            if (!empty($ot['ObjectTemplate']['description'])) {
                $description = (string)$ot['ObjectTemplate']['description'];
            }
            if (!empty($ot['ObjectTemplate']['version'])) {
                $matchedVersion = (int)$ot['ObjectTemplate']['version'];
            }
            if (!empty($ot['ObjectTemplateElement'])) {
                foreach ($ot['ObjectTemplateElement'] as $elDef) {
                    $relation = isset($elDef['object_relation']) ? $elDef['object_relation'] : null;
                    if ($relation === null) {
                        continue;
                    }
                    $categories = isset($elDef['categories']) ? $elDef['categories'] : null;
                    if (is_string($categories)) {
                        $decoded = json_decode($categories, true);
                        $categories = is_array($decoded) ? $decoded : array();
                    }
                    if (!is_array($categories)) {
                        $categories = array();
                    }
                    $relations[$relation] = array(
                        'type' => isset($elDef['type']) ? (string)$elDef['type'] : '',
                        'category' => !empty($categories) ? (string)$categories[0] : 'Other',
                        'to_ids' => isset($elDef['to_ids']) ? (bool)$elDef['to_ids'] : true,
                    );
                }
            }
        }
        $spec = array(
            'meta_category' => $metaCategory,
            'description' => $description,
            'relations' => $relations,
            'matched_version' => $matchedVersion,
        );
        $this->objectTemplateSpec[$cacheKey] = $spec;
        return $spec;
    }

    private function generateUuid()
    {
        App::uses('CakeText', 'Utility');
        return CakeText::uuid();
    }

    /**
     * After _add() returns true, verify the resulting event has as many
     * top-level Attributes and Objects as we submitted — _add logs "dropped"
     * rows on nested validation failures without failing the call itself.
     * Returns a list of per-drop error strings (empty = all good).
     *
     * Uses the Event model's own associations so we don't depend on knowing
     * the right alias for MispAttribute / MispObject (MISP sets those up
     * historically under the "Attribute" / "Object" aliases for back-compat).
     */
    private function verifyEventContents($eventModel, $eventId, array $submittedEvent)
    {
        $expectedAttrs = isset($submittedEvent['Attribute']) ? count($submittedEvent['Attribute']) : 0;
        $expectedObjs = isset($submittedEvent['Object']) ? count($submittedEvent['Object']) : 0;

        $fresh = $eventModel->find('first', array(
            'conditions' => array('Event.id' => $eventId),
            'contain' => array('Attribute', 'Object'),
        ));
        if (empty($fresh)) {
            return array(sprintf('event id=%d could not be re-read after creation', $eventId));
        }

        $actualAttrs = 0;
        if (!empty($fresh['Attribute'])) {
            foreach ($fresh['Attribute'] as $a) {
                $isObjectAttr = (isset($a['object_id']) && (int)$a['object_id'] !== 0);
                $isDeleted = !empty($a['deleted']);
                if (!$isObjectAttr && !$isDeleted) {
                    $actualAttrs++;
                }
            }
        }
        $actualObjs = 0;
        if (!empty($fresh['Object'])) {
            foreach ($fresh['Object'] as $o) {
                if (empty($o['deleted'])) {
                    $actualObjs++;
                }
            }
        }

        $errors = array();
        if ($actualAttrs < $expectedAttrs) {
            $errors[] = sprintf(
                'expected %d top-level attribute(s), saved %d — see audit log for dropped rows',
                $expectedAttrs, $actualAttrs
            );
        }
        if ($actualObjs < $expectedObjs) {
            $errors[] = sprintf(
                'expected %d MISP object(s), saved %d — see audit log for dropped rows',
                $expectedObjs, $actualObjs
            );
        }
        return $errors;
    }

    /**
     * Event::_add returns `true` on success; on failure it returns bool false,
     * an int (for uuid-collision), or one of several string codes. It also
     * populates $validationErrors for model-level validation issues. Flatten
     * whatever shape we got into a list of human-readable strings.
     */
    private function normaliseAddFailure($result, array $validationErrors)
    {
        $errors = array();
        if (is_string($result) && $result !== '') {
            $errors[] = $result;
        } elseif (is_int($result)) {
            $errors[] = sprintf('event with this uuid already exists (id=%d)', $result);
        } elseif ($result === false) {
            $errors[] = 'Event::_add returned false';
        }
        if (!empty($validationErrors)) {
            foreach ($validationErrors as $field => $msgs) {
                if (is_array($msgs)) {
                    foreach ($msgs as $m) {
                        $errors[] = sprintf('%s: %s', $field, (string)$m);
                    }
                } else {
                    $errors[] = sprintf('%s: %s', $field, (string)$msgs);
                }
            }
        }
        if (empty($errors)) {
            $errors[] = 'unspecified event-creation failure';
        }
        return $errors;
    }
}
