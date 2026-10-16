<?php
/**
 * The outline: the whole document on the left, one section of it open
 * on the right.
 *
 * Grouped rather than flat, because a flat list of ten made a reader
 * read all ten to find the one they came for. The three groups sort by
 * the kind of knob — what counts as evidence, what the engine does
 * with it, and what you look at first — so a reader who knows what
 * they want to change reads one group of five at most, and a reader
 * who does not learns what a profile is made of from the headings.
 *
 * Every section still carries the axis it configures. The two are
 * orthogonal and both worth saying: the group is where a setting
 * lives, the axis is what moving it costs. The counts are settings,
 * not bytes — what a reader wants to know before clicking is how much
 * is in there.
 *
 * `Raw JSON` is the same document seen whole rather than another
 * section of it, so it gets its own heading instead of sitting under
 * somebody else's.
 *
 * @var array $sections
 * @var array $groups Group key => heading, in the order to draw them
 * @var string $open
 * @var string $raw The document, for the Raw JSON row's size
 * @var bool $editable
 */
$count = function (array $section) {
    $n = 0;
    foreach ($section['blocks'] as $block) {
        if ($block['kind'] === 'items') {
            $n += count($block['items']);
        } elseif (!empty($block['fields'])) {
            $n += count($block['fields']);
        } elseif ($block['kind'] === 'map') {
            foreach ($block['entries'] as $entry) {
                /* A row whose key is a setting too counts as both. */
                $n += empty($entry['key_field']) ? 1 : 2;
            }
        }
    }
    return $n;
};

/*
 * A section whose group the tool does not name would otherwise vanish
 * from the rail, and a vanished section is unreachable — its pane only
 * opens from here. So the groups are filled by walking the sections,
 * and anything unclaimed lands in the last group rather than nowhere.
 */
$grouped = array_fill_keys(array_keys($groups), array());
$fallback = array_key_last($grouped);
foreach ($sections as $id => $section) {
    $key = isset($section['group']) && isset($grouped[$section['group']])
        ? $section['group']
        : $fallback;
    $grouped[$key][$id] = $section;
}
?>
<nav class="wb-rail" id="ap-rail">
    <?php foreach ($groups as $key => $heading): ?>
        <?php if (empty($grouped[$key])) { continue; } ?>
        <div class="wb-rail-group"><?= h($heading) ?></div>
        <?php foreach ($grouped[$key] as $id => $section): ?>
            <button type="button"
                    class="wb-rail-item <?= $open === $id ? 'is-open' : '' ?>"
                    data-sec="<?= h($id) ?>">
                <span>
                    <span class="mk" data-ap-dirty-mark="<?= h($id) ?>" hidden
                          title="<?= h(__('Unsaved change in this'
                              . ' section')) ?>">&#8961;</span>
                    <?= h($section['title']) ?>
                    <span class="wb-rail-ax"><?= h($section['axis']) ?></span>
                </span>
                <span class="c"><?= h($count($section)) ?></span>
            </button>
        <?php endforeach; ?>
    <?php endforeach; ?>

    <div class="wb-rail-group"><?= h(__('The document')) ?></div>
    <button type="button" class="wb-rail-item <?= $open === 'raw' ? 'is-open' : '' ?>"
            data-sec="raw">
        <span>
            <?= h(__('Raw JSON')) ?>
            <span class="wb-rail-ax"><?= h(__('all three')) ?></span>
        </span>
        <span class="c"><?= h(sprintf('%.1f KB', strlen($raw) / 1024)) ?></span>
    </button>
</nav>
