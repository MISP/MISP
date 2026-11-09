<?php
/**
 * A key→value map: graded organisations, warninglist categories, the
 * TTL buckets and their types, the modules declared per attribute type.
 *
 * **Only the keys the map already carries**, plus a control to add one.
 * §4 of the spec is explicit that an instance with nine hundred
 * organisations must not render nine hundred rows to say something
 * about four of them, and the same restraint applies to every other
 * map here.
 *
 * A map **replaces** on save rather than merging, because a row the
 * analyst removed posts nothing and a merge cannot tell that from a row
 * the form never drew. `__present` is what says the block was on
 * screen; without it an empty map would read as *unchanged*.
 *
 * An entry may carry an `icon`, a `title`, a `desc` line, a `url` its
 * name links to and a `group`; the block may carry `others`, the keys it
 * leaves out, listed behind a click when read rather than edited, and
 * `live`, for a list edited where it is read: its add control goes above
 * the rows. `group_by` `value` heads the rows by their value instead,
 * one heading per `groups` entry, so a row changed while editing can
 * move under its new one; `numbered` counts the tiles, for a list whose
 * order is what it says.
 *
 * @var array $block
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

/*
 * One picker list per map rather than one per row: the four TTL
 * buckets offer the same 194 attribute types, and four copies of that
 * list is three copies too many.
 */
$datalist = null;
if (($block['value_type'] ?? null) === 'types') {
    $datalist = AnalystProfileFormTool::fieldId($block['path'], array('list'));
}

/*
 * A map whose keys are themselves a setting gets a column for it. The
 * TTL buckets are the case: a bucket *is* a number of days, and the
 * days lived in a separate block whose only way of saying which row it
 * belonged to was to print the bucket's name again.
 */
$keyField = !empty($block['key_field_label']);

/*
 * A source too large to offer as a list is offered as a query instead.
 * Organisations are the one: the key is a uuid, the instance holds
 * thousands, and the control that was here asked the analyst to type
 * the uuid — a picker in name and a free-text box in fact.
 *
 * The endpoint is the dashboard's, already ACL'd to every user and
 * already capped at fifty rows, rather than a second one written to
 * say the same thing. A source with no entry here keeps the list it
 * had; only the ones named are queried.
 */
$searchUrl = null;
if (!empty($block['add']['search']) && !empty($block['add']['source'])) {
    $endpoints = array(
        'orgs' => array(
            'controller' => 'dashboards',
            'action' => 'searchOrganisations',
            'ext' => 'json',
        ),
    );
    $source = $block['add']['source'];
    if (isset($endpoints[$source])) {
        $searchUrl = $this->Html->url($endpoints[$source]);
    }
}

/*
 * A list the page can hold, but not one anybody reads to the bottom
 * of. `search` on a source with no endpoint means the options are all
 * here already and the box narrows them: the warninglists are named as
 * sentences — *List of known Microsoft Azure Datacenter IP Ranges* —
 * and a hundred of those in a select is a scroll, not a choice.
 *
 * The select is still what the server draws, and the page swaps it for
 * the combobox. Unlike the organisations above there *is* something
 * behind the control without JS, so the fallback is the thing it
 * enhances rather than a box that does nothing.
 */
$filter = $searchUrl === null && !empty($block['add']['search']);

/*
 * The control a row's value gets when the page adds the row, as
 * against when the server draws it. Without this the row added on the
 * page is the one place in the editor where a grade is typed.
 */
$valueOptions = isset($block['value_options'])
    ? json_encode(array_map(function ($option) {
        // The page draws a state's segment with the same icon the server does.
        if (is_array($option) && !empty($option['icon'])) {
            $option['icon_class'] = $this->FontAwesome->getClass($option['icon']);
        }
        return $option;
    }, $block['value_options']))
    : null;

/*
 * And the sub-rows that control repeats. A `state_map` value is one
 * select per name the row admits, so the page needs those names as
 * well as the vocabulary before it can draw the row the server would
 * have drawn.
 *
 * Keyed by the row's own key rather than one list for the whole map:
 * the modules block draws a module per row and the types each module
 * accepts underneath it, and no two modules accept the same types.
 */
$valueRows = isset($block['value_rows'])
    ? json_encode($block['value_rows'])
    : null;

/*
 * What each option is worth, for a map whose values are priced
 * elsewhere in the same section. Carried on the container rather than
 * per row so the page can repaint every row when the price changes,
 * and `value_factor_path` names the block that sets it — the prices
 * are editable, and a number that stopped following the box that sets
 * it would be worse than no number.
 */
$factors = isset($block['value_factors'])
    ? json_encode($block['value_factors'])
    : null;
$factorName = isset($block['value_factor_path'])
    ? AnalystProfileFormTool::fieldName($block['value_factor_path'])
    : null;

$byValue = ($block['group_by'] ?? null) === 'value' && !empty($block['groups']);
$classes = array('ap-map');
if (($block['display'] ?? '') === 'chips') {
    $classes[] = 'is-chips';
}
// Tiles whose value is a choice show it while they are edited.
if (count($block['value_options'] ?? array()) > 1) {
    $classes[] = 'has-choice';
}
if (!empty($block['numbered'])) {
    $classes[] = 'is-numbered';
}
if (($block['value_type'] ?? null) === 'state_map') {
    $classes[] = 'is-states';
}
// A map read as a drawing of its own (`read_view`); the table is what Edit shows.
if (!empty($block['read_view'])) {
    $classes[] = 'has-read-view';
}
// An ordered list: its tiles are dragged into place, and a pick joins them at the end.
$sortable = !empty($block['sortable']);
if ($sortable) {
    $classes[] = 'is-sortable';
}

/*
 * What the picker may offer: the keys not in the map, and the ones that
 * are, so a row removed while editing can be picked again. The rows on
 * screen are what the picker leaves out.
 */
$offerable = $block['add']['options'] ?? array();
if (!empty($offerable)) {
    $merged = false;
    foreach ($block['entries'] as $entry) {
        if (empty($entry['missing']) && !in_array($entry['key'], $offerable, true)) {
            $offerable[] = $entry['key'];
            $merged = true;
        }
    }
    if ($merged) {
        $names = $block['add']['labels'] ?? array();
        usort($offerable, function ($a, $b) use ($names) {
            return strnatcasecmp($names[$a] ?? $a, $names[$b] ?? $b);
        });
    }
}
?>
<div data-ap-new-label="<?= h(__('Added, not saved yet')) ?>" class="<?= h(implode(' ', $classes)) ?>"<?=
    $byValue ? ' data-ap-group-by-value' : '' ?><?= $factors === null ? '' :
    ' data-ap-factors="' . h($factors) . '"' ?><?= $factorName === null ? '' :
    ' data-ap-factor-name="' . h($factorName) . '"' ?>>
<?php if ($datalist !== null): ?>
    <datalist id="<?= h($datalist) ?>">
        <?php
        $offered = array();
        foreach ($block['entries'] as $entry) {
            foreach (($entry['options'] ?? array()) as $option) {
                if (!isset($entry['taken'][$option])) {
                    $offered[$option] = true;
                }
            }
        }
        ?>
        <?php foreach (array_keys($offered) as $option): ?>
            <option value="<?= h($option) ?>"></option>
        <?php endforeach; ?>
    </datalist>
<?php endif; ?>
<?php if (!empty($block['live'])): ?>
    <?php // Its own search, and the switch that shows the controls that change it. ?>
    <div class="ap-live-head">
        <div class="ap-live-head-t"><?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?></div>
        <div class="ap-live-tools">
            <?php // A list long enough to need narrowing says so with its placeholder. ?>
            <?php if (!empty($block['filter_placeholder'])): ?>
                <label class="ap-live-filter">
                    <i class="fas fa-magnifying-glass" aria-hidden="true"></i>
                    <input type="search" class="form-control form-control-sm" data-ap-live-filter
                           autocomplete="off" spellcheck="false"
                           aria-label="<?= h($block['filter_placeholder']) ?>"
                           placeholder="<?= h($block['filter_placeholder']) ?>">
                </label>
            <?php endif; ?>
            <?php if ($editable): ?>
                <button type="button" class="btn btn-sm btn-outline-primary" data-ap-live-edit>
                    <i class="fas fa-pen me-1" aria-hidden="true"></i><span><?= h(__('Edit')) ?></span>
                </button>
            <?php endif; ?>
        </div>
    </div>
<?php else: ?>
    <?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?>
<?php endif; ?>

<?php
/*
 * What this map currently costs, where the cost is a property of the
 * map as a whole rather than of any row in it. The pinned tier is the
 * case: each pin draws a row on every value carrying none of it, so the
 * price is the number of them and no single row can say so. Advisory,
 * never a refusal — an analyst with a reason to pin six is spending
 * something, and the editor's job is to say what.
 */
?>
<?php if (!empty($block['note'])): ?>
    <p class="ap-map-note"><?= h($block['note']) ?></p>
<?php endif; ?>

<?php if ($editable): ?>
    <input type="hidden"
           name="<?= h(AnalystProfileFormTool::fieldName($block['path'],
               array('__present'))) ?>"
           value="1">
<?php endif; ?>

<?php
// The add control: under the rows, or above them for a list edited where it is read.
$renderAdd = function () use ($block, $editable, $searchUrl, $valueOptions, $valueRows, $filter,
    $offerable, $sortable
) {
    ob_start();
    ?>
<?php if ($editable && !empty($block['add'])): ?>
    <div class="ap-map-add">
        <?php if (!empty($block['add']['title'])): ?>
            <p class="ap-map-add-h"><?= h($block['add']['title']) ?></p>
        <?php endif; ?>
        <div class="ap-map-find">
        <?php // A live list's frame is titled already; its label stays for screen readers. ?>
        <label for="<?= h(AnalystProfileFormTool::fieldId(
            $block['path'], array('add'))) ?>"<?= empty($block['live']) ? '' : ' class="visually-hidden"' ?>>
            <i class="fa-solid fa-plus" aria-hidden="true"></i>
            <?= h($block['add']['label']) ?>
        </label>
        <?php if ($searchUrl !== null): ?>
            <?php
            /*
             * A box that finds rather than a box that accepts. It posts
             * nothing itself — the row it produces carries the key —
             * so it is deliberately outside the naming scheme the merge
             * reads, and a browser with no JS gets a control that does
             * nothing rather than one that writes a uuid-shaped typo
             * into the document.
             */
            ?>
            <div class="ap-pick">
                <input class="form-control form-control-sm" type="search"
                       autocomplete="off" role="combobox"
                       aria-expanded="false" aria-autocomplete="list"
                       id="<?= h(AnalystProfileFormTool::fieldId(
                           $block['path'], array('add'))) ?>"
                       data-ap-pick="1"
                       data-ap-add="<?= h(implode('.', $block['path'])) ?>"
                       data-ap-add-type="<?= h($block['value_type'] ?? '') ?>"
                       data-ap-add-name="<?= h(
                           AnalystProfileFormTool::fieldName(
                               $block['path'])) ?>"
                       data-ap-add-source="<?= h($block['add']['source']) ?>"
                       data-ap-add-url="<?= h($searchUrl) ?>"
                       <?= $valueOptions === null ? '' :
                           'data-ap-add-options="' . h($valueOptions) . '"' ?>
                       data-ap-pick-hint="<?= h(__('type to search')) ?>"
                       data-ap-pick-none="<?= h(__('no match')) ?>"
                       data-ap-pick-unknown="<?= h(__('not an organisation'
                           . ' on this instance')) ?>"
                       placeholder="<?= h(isset($block['add']['placeholder'])
                           ? $block['add']['placeholder']
                           : __('search…')) ?>">
                <div class="ap-pick-list" role="listbox" hidden></div>
            </div>
        <?php elseif (!empty($offerable)): ?>
            <select class="form-select form-select-sm" style="max-width:16rem"
                    id="<?= h(AnalystProfileFormTool::fieldId($block['path'],
                        array('add'))) ?>"
                    data-ap-add="<?= h(implode('.', $block['path'])) ?>"
                    data-ap-add-type="<?= h($block['value_type'] ?? '') ?>"
                    data-ap-add-name="<?= h(AnalystProfileFormTool::fieldName(
                        $block['path'])) ?>"
                    <?php if ($filter): ?>
                        data-ap-add-filter="1"
                        data-ap-pick-placeholder="<?= h(
                            isset($block['add']['placeholder'])
                                ? $block['add']['placeholder']
                                : __('type to filter…')) ?>"
                        data-ap-pick-hint="<?= h(sprintf(
                            __('every %s is already in the table'),
                            strtolower($block['key_label']))) ?>"
                        data-ap-pick-none="<?= h($block['add']['pick_none'] ?? __('no match')) ?>"
                        <?php if (!empty($block['add']['pick_head'])): ?>
                            data-ap-pick-head="<?= h($block['add']['pick_head']) ?>"
                        <?php endif; ?>
                    <?php endif; ?>
                    <?= $valueOptions === null ? '' :
                        'data-ap-add-options="' . h($valueOptions) . '"' ?>
                    <?= $valueRows === null ? '' :
                        'data-ap-add-rows="' . h($valueRows) . '"' ?>>
                <option value=""><?= h(__('pick one…')) ?></option>
                <?php foreach ($offerable as $option): ?>
                    <?php // What a tile drawn for this pick shows beside its name. ?>
                    <option value="<?= h($option) ?>"<?= empty($block['add']['subs'][$option])
                        ? '' : ' data-desc="' . h($block['add']['subs'][$option]) . '"' ?><?=
                        empty($block['add']['icons'][$option]) ? '' : ' data-icon="'
                        . $this->FontAwesome->getClass($block['add']['icons'][$option]) . '"' ?>><?= h(
                        $block['add']['labels'][$option] ?? $option) ?></option>
                <?php endforeach; ?>
            </select>
        <?php else: ?>
            <input class="form-control form-control-sm" type="search"
                   style="max-width:16rem"
                   id="<?= h(AnalystProfileFormTool::fieldId($block['path'],
                       array('add'))) ?>"
                   data-ap-add="<?= h(implode('.', $block['path'])) ?>"
                   data-ap-add-type="<?= h($block['value_type'] ?? '') ?>"
                   data-ap-add-name="<?= h(AnalystProfileFormTool::fieldName(
                       $block['path'])) ?>"
                   data-ap-add-source="<?= h($block['add']['source']) ?>"
                   <?= $valueOptions === null ? '' :
                       'data-ap-add-options="' . h($valueOptions) . '"' ?>
                   <?= $valueRows === null ? '' :
                       'data-ap-add-rows="' . h($valueRows) . '"' ?>
                   placeholder="<?= h(__('search…')) ?>">
        <?php endif; ?>
        <?php if (!empty($block['add']['help'])): ?>
            <p class="ap-map-add-help"><?= h($block['add']['help']) ?></p>
        <?php endif; ?>
        </div>
        <?php
        /*
         * Filling a map from a list the analyst just wrote elsewhere.
         * The attribution galaxies are the case: they overlap heavily
         * with the ranked ones by design, and retyping a list you just
         * wrote is how two lists that should agree drift apart.
         *
         * It adds rows and saves nothing by itself — the rows it draws
         * are the same ones the picker draws, so the save path is
         * unchanged and the analyst still sees what they are about to
         * store before they store it.
         */
        ?>
        <?php if (!empty($block['add']['copy_from']['keys'])): ?>
            <?php
            $copy = $block['add']['copy_from'];
            // What a press would add: the keys the map does not carry yet, by name.
            $pending = array_values(array_diff($copy['keys'],
                array_column($block['entries'], 'key')));
            $pendingNames = array_map(function ($key) use ($copy) {
                return $copy['names'][$key] ?? $key;
            }, $pending);
            ?>
            <div class="ap-map-copy">
                <button type="button" class="ap-copy-btn"
                        data-ap-copy="<?= h(json_encode($pending)) ?>"
                        data-ap-copy-value="<?= h($copy['value'] ?? '') ?>"
                        <?= empty($pending) ? 'disabled' : '' ?>
                        title="<?= h(empty($pending)
                            ? __('They all count already.')
                            : implode(', ', $pendingNames)) ?>">
                    <span class="ap-copy-ico" aria-hidden="true"><i class="fa-solid fa-wand-magic-sparkles"></i></span>
                    <span class="ap-copy-t"><?= h($copy['label']) ?></span>
                    <span class="ap-copy-n"><?= h(count($pending)) ?></span>
                </button>
                <?php if (!empty($copy['help'])): ?>
                    <span class="ap-map-add-help"><?= h(empty($pending)
                        ? __('They all count already.')
                        : $copy['help']) ?></span>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        <?php if (!empty($block['live']) && !$sortable): ?>
            <?php // What was picked and not saved yet waits here, not among the saved entries. ?>
            <div class="ap-map-new" data-ap-new-wrap hidden>
                <p class="ap-map-new-h"><?= h(__('Added, not saved yet')) ?>
                    <span class="ap-map-grp-n" data-ap-new-n>0</span></p>
                <table class="wb-tbl" data-ap-new-table><tbody data-ap-new-rows></tbody></table>
            </div>
        <?php endif; ?>
    </div>
<?php endif; ?>
    <?php
    return ob_get_clean();
};
?>
<?php if (!empty($block['live'])) { echo $renderAdd(); } ?>

<?php
/*
 * An empty map still draws its table, folded away, wherever a row can
 * be added: the page adds a row by appending to a `tbody`, and a map
 * with no rows had no `tbody` to append to — so on the profile that
 * most needs the control, the control did nothing at all. The note and
 * the table trade places when the first row arrives.
 */
$hasRows = !empty($block['entries']);
$canAdd = $editable && !empty($block['add']);
?>
<?php
$renderLegend = function () use ($block) {
    if (empty($block['value_legend']['entries'])) {
        return '';
    }
    ob_start();
    ?>
    <?php
    /*
     * What the options in this map's value column actually are. A map
     * whose values are a closed vocabulary can be edited without the
     * reader knowing what either word means — `known` reads as *known
     * bad* and means *known infrastructure* — so the vocabulary is
     * spelled out under the table rather than in a tooltip on it.
     *
     * Under rather than over: it is reference, read once, and a reader
     * who already knows the words should reach the control first. A
     * live list says it above (`legend_above`), where its chips are
     * read before the rows that use them.
     */
    $legend = $block['value_legend'];
    // The chip each value is drawn with, where its options carry one.
    $looks = array();
    foreach ($block['value_options'] ?? array() as $option) {
        if (is_array($option) && isset($option['icon'])) {
            $looks[(string)$option['value']] = $option;
        }
    }
    ?>
    <?php if (($legend['layout'] ?? '') === 'cards'): ?>
        <?php // One card per value, side by side: what it means, then what it does here. ?>
        <div class="ap-legend is-cards">
            <?php if (!empty($legend['title'])): ?>
                <p class="ap-legend-h"><?= h($legend['title']) ?></p>
            <?php endif; ?>
            <div class="ap-legend-cards">
                <?php foreach ($legend['entries'] as $item): ?>
                    <?php $look = $looks[(string)($item['value'] ?? '')] ?? null; ?>
                    <section class="ap-legend-card t-<?= h($look['tone'] ?? 'plain') ?>">
                        <p class="ap-legend-card-h">
                            <?php if ($look !== null): ?>
                                <i class="<?= $this->FontAwesome->getClass($look['icon']) ?>" aria-hidden="true"></i>
                            <?php endif; ?>
                            <?= h($item['label']) ?>
                        </p>
                        <p class="ap-legend-card-m"><?= h($item['meaning']) ?></p>
                        <?php if (!empty($item['effect'])): ?>
                            <p class="ap-legend-card-e"><span><?= h(__('Here')) ?></span><?= h($item['effect']) ?></p>
                        <?php endif; ?>
                    </section>
                <?php endforeach; ?>
            </div>
            <?php if (!empty($legend['note'])): ?>
                <p class="ap-legend-note"><?= h($legend['note']) ?></p>
            <?php endif; ?>
        </div>
    <?php elseif (($legend['layout'] ?? '') === 'inline'): ?>
        <div class="ap-legend is-inline">
            <?php if (!empty($legend['title'])): ?>
                <p class="ap-legend-h"><?= h($legend['title']) ?></p>
            <?php endif; ?>
            <ul class="ap-legend-list">
                <?php foreach ($legend['entries'] as $item): ?>
                    <?php $look = $looks[(string)($item['value'] ?? '')] ?? null; ?>
                    <li>
                        <span class="mod-chip t-<?= h($look['tone'] ?? 'plain') ?>">
                            <?php if ($look !== null): ?>
                                <i class="<?= $this->FontAwesome->getClass($look['icon']) ?>" aria-hidden="true"></i>
                            <?php endif; ?>
                            <?= h($item['label']) ?>
                        </span>
                        <?php if (!empty($item['effect'])): ?>
                            <span class="ap-legend-does"><?= h($item['effect']) ?></span>
                        <?php endif; ?>
                        <a href="#" class="wb-i" onclick="return false;"
                           title="<?= h($item['meaning']) ?>">i</a>
                    </li>
                <?php endforeach; ?>
            </ul>
            <?php if (!empty($legend['note'])): ?>
                <p class="ap-legend-note"><?= h($legend['note']) ?></p>
            <?php endif; ?>
        </div>
    <?php else: ?>
    <div class="ap-legend">
        <?php if (!empty($legend['title'])): ?>
            <p class="ap-legend-h"><?= h($legend['title']) ?></p>
        <?php endif; ?>
        <dl>
            <?php foreach ($legend['entries'] as $item): ?>
                <dt><?= h($item['label']) ?></dt>
                <dd>
                    <?= h($item['meaning']) ?>
                    <?php if (!empty($item['effect'])): ?>
                        <span class="ap-legend-does"><?=
                            h($item['effect']) ?></span>
                    <?php endif; ?>
                </dd>
            <?php endforeach; ?>
        </dl>
        <?php if (!empty($legend['note'])): ?>
            <p class="ap-legend-note"><?= h($legend['note']) ?></p>
        <?php endif; ?>
    </div>
    <?php endif; ?>
    <?php
    return ob_get_clean();
};
$legendAbove = !empty($block['legend_above']);
?>
<?php if ($legendAbove) { echo $renderLegend(); } ?>
<?php // Empty, said after what its values mean. ?>
<?php if (!$hasRows || $canAdd): ?>
    <?php
    /*
     * A map says it is empty in its own words where it has any. The
     * generated sentence is `No <value column> set`, which reads only
     * while that column header happens to be a plain noun: *Means*
     * gave **No means set** and *Answers from* gave **No answers from
     * set**. The header names a column, not the thing the map holds,
     * so a block that knows what its rows are says it.
     */
    $emptyLabel = !empty($block['empty_label'])
        ? $block['empty_label']
        : sprintf(__('No %s set'), strtolower($block['value_label']));
    $emptyNote = !empty($block['empty_note'])
        ? $block['empty_note']
        : __('The shipped behaviour applies.');
    ?>
    <div class="wb-empty" data-ap-map-empty="1" <?= $hasRows ? 'hidden' : '' ?>>
        <span class="wb-empty-h"><?= h($emptyLabel) ?></span>
        <span><?= h($emptyNote) ?></span>
    </div>
<?php endif; ?>
<?php if (!empty($block['read_view'])): ?>
    <div class="ap-read-view">
        <?= $this->element('AnalystProfiles/' . $block['read_view'], array('block' => $block)) ?>
    </div>
<?php endif; ?>
<?php
/*
 * A box that narrows the rows already in the table, which is a
 * different thing from the picker above: that one finds a row to
 * *add*, this one finds a row you already have. Worth drawing only
 * past the point where scanning stops working, and hidden until the
 * page can drive it — a search box that does nothing is worse than
 * none.
 */
$rowFilter = empty($block['live']) && !empty($block['row_filter'])
    && count($block['entries']) >= (int)$block['row_filter'];
?>
<?php if ($rowFilter): ?>
    <div class="ap-row-filter" hidden data-ap-rowfilter-wrap>
        <input class="form-control form-control-sm" type="search"
               style="max-width:16rem"
               data-ap-rowfilter="1"
               data-ap-rowfilter-empty="<?= h(__('no row matches')) ?>"
               placeholder="<?= h(!empty($block['row_filter_placeholder'])
                   ? $block['row_filter_placeholder']
                   : __('filter the rows below…')) ?>">
        <span class="wb-sub" data-ap-rowfilter-count></span>
    </div>
<?php endif; ?>
<?php if ($hasRows || $canAdd): ?>
    <table class="wb-tbl" <?= $hasRows ? '' : 'hidden' ?>>
        <thead>
            <tr>
                <th style="width:<?= $keyField ? '11rem' : '34%' ?>">
                    <?= h($block['key_label']) ?>
                </th>
                <?php if ($keyField): ?>
                    <th style="width:6.5rem">
                        <?= h($block['key_field_label']) ?>
                    </th>
                <?php endif; ?>
                <th><?= h($block['value_label']) ?></th>
                <?php if ($editable && !empty($block['add'])): ?>
                    <th class="r" style="width:3rem"></th>
                <?php endif; ?>
            </tr>
        </thead>
        <tbody>
            <?php
            $columns = 2 + ($keyField ? 1 : 0) + ($editable && !empty($block['add']) ? 1 : 0);
            /*
             * The rows in the order drawn, with their headings. Headed by
             * value, every heading is drawn and an empty one hidden, so a
             * row edited into it has somewhere to go; otherwise entries
             * that name a group arrive sorted by it.
             */
            $sequence = array();
            if ($byValue) {
                $members = array();
                foreach ($block['entries'] as $entry) {
                    $members[(string)$entry['value']][] = $entry;
                }
                foreach ($block['groups'] as $value => $group) {
                    $rows = $members[(string)$value] ?? array();
                    unset($members[(string)$value]);
                    $sequence[] = array('heading' => $group['label'], 'note' => $group['note'] ?? '',
                        'icon' => $group['icon'] ?? null, 'badge' => $group['badge'] ?? null,
                        'tone' => $group['tone'] ?? null, 'n' => count($rows), 'value' => (string)$value);
                    foreach ($rows as $entry) {
                        $sequence[] = array('entry' => $entry);
                    }
                }
                foreach ($members as $rows) {
                    foreach ($rows as $entry) {
                        $sequence[] = array('entry' => $entry);
                    }
                }
            } else {
                $groupSizes = array_count_values(array_filter(array_map(function ($entry) {
                    return isset($entry['group']) ? $entry['group'] : null;
                }, $block['entries'])));
                $group = null;
                foreach ($block['entries'] as $entry) {
                    if (isset($entry['group']) && $entry['group'] !== $group) {
                        $group = $entry['group'];
                        $sequence[] = array('heading' => $group,
                            'note' => $block['group_notes'][$group] ?? '',
                            'icon' => $block['group_looks'][$group]['icon'] ?? null,
                            'tone' => $block['group_looks'][$group]['tone'] ?? null,
                            'n' => $groupSizes[$group], 'value' => null);
                    }
                    $sequence[] = array('entry' => $entry);
                }
            }
            ?>
            <?php foreach ($sequence as $step): ?>
                <?php if (isset($step['heading'])): ?>
                    <tr class="wb-grp ap-map-grp<?= empty($step['tone']) ? '' : ' t-' . h($step['tone']) ?>"<?= $step['value'] === null ? ''
                        : ' data-ap-grp-value="' . h($step['value']) . '"' ?><?= $step['n'] === 0 ? ' hidden' : '' ?>>
                        <td colspan="<?= $columns ?>"><?php if (!empty($step['badge'])): ?><span class="ap-map-grp-badge" aria-hidden="true"><?=
                            h($step['badge']) ?></span><?php endif; ?><?php if ($step['icon'] !== null): ?><i class="<?=
                            $this->FontAwesome->getClass($step['icon']) ?> ap-map-grp-ico" aria-hidden="true"></i><?php
                            endif; ?><?= h($step['heading']) ?>
                            <span class="ap-map-grp-n"><?= h($step['n']) ?></span>
                            <?php if ($step['note'] !== ''): ?>
                                <span class="ap-map-grp-note"><?= h($step['note']) ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php continue; ?>
                <?php endif; ?>
                <?php $entry = $step['entry']; ?>
                <?php
                /*
                 * An entry is one field with a key beside it, so the
                 * same renderer draws a grade, a category, a bucket of
                 * types and a module state map.
                 */
                $field = $entry + array('label' => $entry['key']);
                // A live list's value reads as text until Edit shows its controls.
                $field['live'] = !empty($block['live']);
                $rowClass = empty($entry['missing']) ? '' : 'is-off';
                if (!empty($entry['class'])) {
                    $rowClass = trim($rowClass . ' ' . $entry['class']);
                }
                ?>
                <?php
                /*
                 * The key, on the row, so the picker can leave out
                 * what the map already carries. A search answers
                 * whatever it matches; the rows on screen are what
                 * says which of those are still a choice.
                 */
                ?>
                <tr class="<?= h($rowClass) ?>"
                    data-ap-key="<?= h($entry['key']) ?>"<?= empty($entry['title'])
                        ? '' : ' title="' . h($entry['title']) . '"' ?>>
                    <td>
                        <div class="fw-semibold"><?php if (!empty($entry['icon'])): ?><i class="<?=
                            $this->FontAwesome->getClass($entry['icon']) ?> ap-map-ico" aria-hidden="true"></i><?php
                            endif; ?><?php if (!empty($entry['url'])): ?><a class="ap-map-link" href="<?=
                            h($this->Html->url($entry['url'])) ?>"><?= h($entry['label']) ?></a><?php
                            else: ?><?= h($entry['label']) ?><?php endif; ?></div>
                        <?php
                        /*
                         * What a reader needs beside the name while
                         * they are choosing, rather than two blocks
                         * further down: where the module answers from,
                         * and whether it can answer at all.
                         */
                        ?>
                        <?php if (!empty($entry['tags'])): ?>
                            <div class="ap-tags">
                                <?php foreach ($entry['tags'] as $tag): ?>
                                    <span class="pill t-<?= h($tag['tone']) ?>"
                                        <?= empty($tag['title']) ? '' :
                                            'title="' . h($tag['title']) . '"' ?>
                                    ><?= h($tag['label']) ?></span>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($entry['sub_label'])): ?>
                            <div class="wb-sub"><?= h($entry['sub_label']) ?></div>
                        <?php endif; ?>
                        <?php if (!empty($entry['desc']) && empty($entry['missing'])): ?>
                            <div class="wb-sub ap-map-desc"><?= h($entry['desc']) ?></div>
                        <?php endif; ?>
                        <?php if (!empty($entry['missing']) && empty($entry['missing_in_group'])): ?>
                            <?php
                            /*
                             * Why the row is dimmed, in the block's own
                             * words where it has them. One hardcoded
                             * sentence could only ever be right for one
                             * map: a graded organisation this instance
                             * has never heard of and a module it has
                             * merely switched off are different facts,
                             * and the reader's next move differs too.
                             */
                            ?>
                            <div class="wb-sub ap-map-missing"><?= h(
                                !empty($entry['missing_note'])
                                    ? $entry['missing_note']
                                    : __('Defined in the profile,'
                                        . ' unknown on this instance.')
                            ) ?></div>
                        <?php endif; ?>
                    </td>
                    <?php if ($keyField): ?>
                    <td class="ap-map-key-field">
                        <?php if (empty($entry['key_field'])): ?>
                            <span class="wb-sub">&mdash;</span>
                        <?php else: ?>
                            <?= $this->element('AnalystProfiles/field', array(
                                'field' => $entry['key_field'],
                                'editable' => $editable,
                            )) ?>
                        <?php endif; ?>
                    </td>
                    <?php endif; ?>
                    <td>
                        <?php
                        /*
                         * A row that states rather than takes. The
                         * default lifetime holds every type nobody
                         * assigned, which is not a list anybody edits.
                         */
                        ?>
                        <?php if (isset($entry['note'])): ?>
                            <span class="wb-sub"><?= h($entry['note']) ?></span>
                        <?php else: ?>
                            <div class="ap-map-val">
                                <?= $this->element('AnalystProfiles/field',
                                    array(
                                        'field' => $field,
                                        'editable' => $editable,
                                        'datalist' => $datalist,
                                    )) ?>
                                <?php
                                /*
                                 * What the chosen option is worth,
                                 * beside the option. The select says
                                 * `B — Usually reliable` and the
                                 * number it multiplies by was four
                                 * hundred pixels below in a block of
                                 * its own; a grade is a letter until
                                 * this is next to it.
                                 */
                                ?>
                                <?php if ($factors !== null): ?>
                                    <span class="ap-factor" data-ap-factor><?=
                                        h(isset($entry['factor'])
                                            && $entry['factor'] !== null
                                            ? $entry['factor']
                                            : '') ?></span>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    </td>
                    <?php
                    /*
                     * A row can be removed only where the key set is
                     * open. The four shelf-life buckets are the
                     * closed one — they are a fixed vocabulary, and a
                     * cross beside `Short` offers to delete something
                     * that cannot be deleted. The presence of an add
                     * control is what says which kind a map is.
                     */
                    ?>
                    <?php if ($editable && !empty($block['add'])): ?>
                        <td class="r">
                            <button type="button" class="wb-drop"
                                    data-ap-drop="<?= h(
                                        AnalystProfileFormTool::fieldId(
                                            $entry['path']
                                        )) ?>"
                                    title="<?= h(__('Remove this row')) ?>"
                                    aria-label="<?= h(__('Remove this row')) ?>">
                                <i class="fa-solid fa-trash-can" aria-hidden="true"></i>
                            </button>
                        </td>
                    <?php endif; ?>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>

<?php if (!$editable && !empty($block['others']['items'])): ?>
    <details class="ap-map-others">
        <summary>
            <i class="fa-solid fa-chevron-right" aria-hidden="true"></i>
            <?= h($block['others']['label']) ?>
        </summary>
        <p class="ap-map-others-list">
            <?php foreach ($block['others']['items'] as $other): ?>
                <span><?= h($other) ?></span>
            <?php endforeach; ?>
        </p>
    </details>
<?php endif; ?>

<?php if (empty($block['live'])) { echo $renderAdd(); } ?>

<?php if (!$legendAbove) { echo $renderLegend(); } ?>
</div>
