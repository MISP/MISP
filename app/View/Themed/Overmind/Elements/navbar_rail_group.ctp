<?php
/**
 * A top-level group of the rail: its trigger and its panel, whose columns
 * are the runs of entries between dividers. A group holding a nested group
 * is a wide panel; the others are a single column.
 *
 * @var array $item
 * @var bool $alignEnd
 */
$id = h($item['id'] ?? '');
$tourAttr = empty($item['id']) ? '' : ' data-tour="nav-' . $id . '"';
$isActive = !empty($item['active']);
$currentAttr = $isActive ? ' aria-current="true"' : '';
$glyph = $this->element('navbar_rail_glyph', ['item' => $item]);
?>
<?php if (!empty($item['children'])): ?>
    <?php
        $panelId = 'rail-p-' . $id;
        $mega = false;
        $sections = [[]];
        foreach ($item['children'] as $child) {
            if (!empty($child['divider'])) {
                $sections[] = [];
                continue;
            }
            if (!empty($child['children'])) {
                $mega = true;
            }
            $sections[count($sections) - 1][] = $child;
        }
        $sections = array_values(array_filter($sections));
        // In a wide panel, a run of one or two loose entries joins a
        // neighbouring loose run, after a divider, instead of standing as a
        // column of its own.
        if ($mega) {
            $isLoose = function ($section) {
                foreach ($section as $entry) {
                    if (!empty($entry['children'])) {
                        return false;
                    }
                }
                return true;
            };
            $merged = true;
            while ($merged) {
                $merged = false;
                foreach ($sections as $s => $section) {
                    if (count($section) > 2 || !$isLoose($section)) {
                        continue;
                    }
                    if (isset($sections[$s + 1]) && $isLoose($sections[$s + 1])) {
                        $sections[$s + 1] = array_merge($section, [['divider' => true]], $sections[$s + 1]);
                    } elseif ($s > 0 && $isLoose($sections[$s - 1])) {
                        $sections[$s - 1] = array_merge($sections[$s - 1], [['divider' => true]], $section);
                    } else {
                        continue;
                    }
                    unset($sections[$s]);
                    $sections = array_values($sections);
                    $merged = true;
                    break;
                }
            }
        }
    ?>
    <li class="rail-group" data-group="<?= $id ?>"<?= $tourAttr ?><?= empty($alignEnd) ? '' : ' data-end' ?>>
        <button type="button" class="rail-trigger" aria-expanded="false" aria-controls="<?= $panelId ?>"<?= $currentAttr ?><?= empty($item['image']) ? '' : ' title="' . h($item['label']) . '"' ?>>
            <?= $glyph ?>
            <span class="<?= empty($item['image']) ? 'rail-lbl' : 'rail-who' ?>"><?= h($item['label']) ?></span>
            <span class="rail-caret" aria-hidden="true"></span>
        </button>
        <div class="rail-panel rail-panel--<?= $mega ? 'mega' : 'compact' ?><?= $isActive ? ' rail-panel--current' : '' ?>" id="<?= $panelId ?>">
            <div class="rail-phead" aria-hidden="true">
                <?php if (!empty($item['image'])): ?>
                    <?= $glyph ?>
                <?php else: ?>
                    <span class="rail-hex"><?php if (!empty($item['icon'])): ?><i class="<?= h($item['icon']) ?> fa-fw"></i><?php endif; ?></span>
                <?php endif; ?>
                <span class="rail-ptitle"><?= h($item['label']) ?></span>
            </div>
            <div class="rail-cols">
                <?php foreach ($sections as $s => $section): ?>
                    <ul class="rail-col">
                        <?php foreach ($section as $j => $child): ?>
                            <?= $this->element('navbar_rail_item', ['item' => $child, 'subId' => $panelId . '-' . $s . '-' . $j]) ?>
                        <?php endforeach; ?>
                    </ul>
                <?php endforeach; ?>
            </div>
        </div>
    </li>
<?php else: ?>
    <li class="rail-group"<?= $tourAttr ?>>
        <a class="rail-trigger" href="<?= h($item['url']) ?>"<?= $currentAttr ?>>
            <?= $glyph ?>
            <span class="rail-lbl"><?= h($item['label']) ?></span>
        </a>
    </li>
<?php endif; ?>
