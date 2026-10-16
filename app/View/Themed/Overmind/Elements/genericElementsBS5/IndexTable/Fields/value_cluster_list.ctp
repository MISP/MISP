<?php
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
/**
 * The galaxy clusters an occurrence is attributed to.
 *
 * **The occurrences pane could not see them at all.** A galaxy tag
 * reaches a row on either scope and every surface here dropped it —
 * `Fields/tag_list`'s rule that a cluster is not a label, inherited
 * without being re-argued. What it missed is that the Overview's
 * context card answers *what is this value attributed to* and the
 * table's question is *which occurrences*: on `8.8.8.8`, 9 of 26 rows
 * carry a cluster and 26 distinct ones sit on the page, none of them
 * reachable from the tab the reader is on.
 *
 * **Already ruled on, already named.** `ValueIntelligence::attachClusters`
 * resolves each row's galaxy tags through `fetchGalaxyClusters`, so a
 * tag whose cluster this viewer may not know is absent from the row
 * before it reaches here — this element draws what it is given and
 * makes no visibility decision of its own.
 *
 * Each cluster is a cluster chip, its galaxy on the rail since nothing
 * else in the cell names it. `attachClusters` orders by galaxy, so a
 * cell holding several reads in the card's order.
 *
 * **The reader's order runs before the fold.** Three clusters are
 * drawn and the rest fold, so which galaxy leads decides what is on
 * the page — a cell showing two pieces of tooling and folding the
 * threat actor behind a `+2` is the case the tiers exist for. The
 * ranking key is the galaxy `type`, which `attachClusters` carries
 * beside the display name for exactly this; ties keep the galaxy-then-
 * cluster order that method sorted into, so a profile with no opinion
 * changes nothing.
 *
 * Expected:
 *   $field['data_path']    `Cluster` — `name`, `galaxy`, `type`,
 *                          `tag_name`
 *   $field['max_visible']  clusters drawn before the `+N` fold; 3
 *   $field['plan']         the reader's label priority, optional —
 *                          absent, or declaring no galaxy, and the
 *                          clusters are drawn as they arrived
 */
$maxVisible = isset($field['max_visible'])
    ? (int)$field['max_visible']
    : 3;

$clusters = Hash::extract($row, $field['data_path']);
if (empty($clusters) || !is_array($clusters)) {
    return;
}

$plan = ValueLabelPriority::planFor(
    isset($field['plan']) ? $field['plan'] : null
);
if (ValueLabelPriority::declares($plan, ValueLabelPriority::GALAXIES)) {
    foreach ($clusters as $at => $cluster) {
        $clusters[$at]['key'] = isset($cluster['type'])
            ? $cluster['type']
            : null;
    }
    $clusters = ValueLabelPriority::labels(
        $clusters,
        $plan,
        ValueLabelPriority::GALAXIES
    );
}

$chips = array();
foreach (array_values($clusters) as $cluster) {
    $chips[] = array(
        'id' => isset($cluster['id']) ? $cluster['id'] : null,
        'value' => $cluster['name'],
        'galaxy' => isset($cluster['galaxy']) ? $cluster['galaxy'] : '',
    );
}
$hiddenCount = max(0, count($chips) - $maxVisible);
?>
<div class="tag-container d-inline-flex flex-wrap align-items-center">
    <?= $this->TagChip->clusters(array_slice($chips, 0, $maxVisible)) ?>
    <?= $this->TagChip->clusters(
        array_slice($chips, $maxVisible),
        array('class' => 'd-none extra-tag')
    ) ?>

    <?php if ($hiddenCount > 0): ?>
        <span class="badge bg-secondary text-white me-1 mb-1 tag-expand"
              style="cursor:pointer;"
              data-hidden="<?= (int)$hiddenCount ?>"
              onclick="toggleTags(this)">+<?= h($hiddenCount) ?></span>
    <?php endif; ?>
</div>
