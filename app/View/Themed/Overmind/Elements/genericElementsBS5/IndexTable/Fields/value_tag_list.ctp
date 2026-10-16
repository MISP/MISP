<?php
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
/**
 * The labels on an occurrence — the ones on the attribute and the ones
 * on the event carrying it, as one list.
 *
 * `Fields/tag_list` draws one list from one path, which on this page
 * meant the column showed `attribute_tags` and nothing else. That is a
 * minority of what anybody has said: an analyst tags the report far
 * more often than the indicator inside it, and on the verification
 * instance `8.8.8.8` carries **7 distinct attribute tags** against
 * **48 distinct event tags** across its twenty events — the second set
 * holding every `tlp:`, the `type:OSINT` marking, and the ATT&CK
 * clusters.
 *
 * **Attribute tags first, then the event's.** The order is the strength
 * of the claim, not the alphabet: a tag on this row is about this
 * occurrence, and a tag on its event is about the report the occurrence
 * arrived in. When the cap bites it is therefore the weaker set that
 * folds behind the `+N`.
 *
 * **A tag on both is drawn once.** `tlp:white` on the attribute and on
 * its event is one statement made twice, and two chips would read as
 * two sources agreeing.
 *
 * **Neither scope is marked on the chip.** An event's labelling covers
 * the attributes inside it, so which of the two rows carries the tag is
 * a fact about where MISP stored it rather than about what was said of
 * this occurrence — and a glyph inside every chip of the commoner set
 * spent ink on that distinction in every cell of the table.
 *
 * **Galaxy tags are skipped in both scopes**, which is
 * `Fields/tag_list`'s own rule and is kept rather than reasoned about
 * again here: a cluster is not a label and the page draws it as a
 * cluster, in the context card.
 *
 * **`max_visible` is the caller's, and the two callers differ.** The
 * tab's table shows four, which is `Fields/tag_list`'s own number and
 * right for a table a reader came to read. The Overview's preview shows
 * **two**: chips wrap one per line in a 200px column, so four of them
 * made a 37px row 100px tall and took that card from 433px to 756 —
 * undoing, in one column, the whole of what shortened it. Two lines and
 * a `+N` is a summary; eight rows of four-line cells is the table
 * again.
 *
 * **The reader's own order runs before the fold, not after it.** At
 * four chips and at the Overview's one, which taxonomy sits first
 * decides what is on the page rather than merely what is read first —
 * a column showing `type:OSINT` and folding `tlp:red` behind a `+7` is
 * the case the tiers exist to prevent. So the profile is applied to
 * the merged list and `max_visible` cuts what it produced.
 *
 * **Inside a tier the two scopes keep their order**, because ties keep
 * arrival order and the merge above put the attribute's tags first. A
 * profile with no opinion about a namespace therefore leaves the
 * strength-of-claim order exactly as it was, and one with an opinion
 * overrides it for the namespaces it named and for no others.
 *
 * Expected:
 *   $field['data_path']        attribute tags (AttributeTag)
 *   $field['event_data_path']  event tags (EventTag), optional — with
 *                              it absent this renders the attribute
 *                              scope alone
 *   $field['max_visible']      chips drawn before the `+N` fold; 4
 *   $field['plan']             the reader's label priority, optional —
 *                              absent, or declaring no taxonomy, and
 *                              the chips are drawn in the order they
 *                              were merged in
 */
$maxVisible = isset($field['max_visible'])
    ? (int)$field['max_visible']
    : 4;

/**
 * `AttributeTag`/`EventTag` rows, or bare tags, to one shape.
 *
 * @param mixed $raw
 * @return array
 */
$collect = function ($raw) {
    $out = array();
    if (empty($raw) || !is_array($raw)) {
        return $out;
    }
    if (isset($raw['name'])) {
        $raw = array($raw);
    }
    foreach ($raw as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        if (isset($entry['Tag'])) {
            $tag = $entry['Tag'];
            $local = $entry['local'] ?? ($tag['local'] ?? false);
        } elseif (isset($entry['name'])) {
            $tag = $entry;
            $local = $entry['local'] ?? false;
        } else {
            continue;
        }
        // Galaxy tags live in both tables; the context card draws them.
        if (empty($tag['name']) || !empty($tag['is_galaxy'])) {
            continue;
        }
        $out[] = array(
            'tag' => $tag,
            'local' => !empty($local),
        );
    }
    return $out;
};

$chips = $collect(Hash::extract($row, $field['data_path']));
if (!empty($field['event_data_path'])) {
    $seen = array();
    foreach ($chips as $chip) {
        $seen[$chip['tag']['name']] = true;
    }
    foreach ($collect(
        Hash::extract($row, $field['event_data_path'])
    ) as $chip) {
        if (!isset($seen[$chip['tag']['name']])) {
            $seen[$chip['tag']['name']] = true;
            $chips[] = $chip;
        }
    }
}

if (empty($chips)) {
    return;
}

/*
 * `namespaceOf` is the key a profile lists a taxonomy by, and the full
 * tag name is what the handling order inside `tlp` and `pap` is read
 * from. A galaxy tag never reaches here, so no chip is ranked under
 * the wrong dimension.
 */
$plan = ValueLabelPriority::planFor(
    isset($field['plan']) ? $field['plan'] : null
);
if (ValueLabelPriority::declares($plan, ValueLabelPriority::TAXONOMIES)) {
    foreach ($chips as $at => $chip) {
        $chips[$at]['key'] = ValueLabelPriority::namespaceOf(
            $chip['tag']['name']
        );
        $chips[$at]['name'] = $chip['tag']['name'];
    }
    $chips = ValueLabelPriority::labels(
        $chips,
        $plan,
        ValueLabelPriority::TAXONOMIES
    );
}

$hiddenCount = max(0, count($chips) - $maxVisible);
?>
<?php
$rows = array_map(function ($chip) {
    return ['Tag' => $chip['tag'], 'local' => $chip['local']];
}, array_values($chips));
?>
<div class="tag-container d-inline-flex flex-wrap align-items-center gap-1">
    <?= $this->TagChip->collection(array_slice($rows, 0, $maxVisible), ['searchUrl' => '']) ?>
    <?= $this->TagChip->collection(array_slice($rows, $maxVisible), [
        'searchUrl' => '',
        'class' => 'd-none extra-tag',
    ]) ?>

    <?php if ($hiddenCount > 0): ?>
        <span class="badge bg-secondary text-white me-1 mb-1 tag-expand"
              style="cursor:pointer;"
              data-hidden="<?= (int)$hiddenCount ?>"
              onclick="toggleTags(this)">+<?= h($hiddenCount) ?></span>
    <?php endif; ?>
</div>
