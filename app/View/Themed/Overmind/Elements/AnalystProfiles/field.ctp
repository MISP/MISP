<?php
/**
 * One setting, as whatever control its type asks for.
 *
 * Seven types and no per-section code: every field in the view-model
 * carries its own `path`, which is both the POST name and the address
 * `AnalystProfileFormTool::merge()` writes back to. A section that
 * needed its own renderer would be a section whose fields the merge
 * could not find.
 *
 * `editable` false draws the same field as text. Not a disabled input:
 * a disabled input still looks like something you could have changed,
 * and the read-only page is for a profile that is somebody else's.
 *
 * @var array $field
 * @var bool $editable
 * @var string|null $datalist The id of the picker's option list
 * @var string|null $datalist The id of the picker's option list
 * @var array|null $extra Segments appended to the path, for a field
 *                        inside a map row
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$extra = isset($extra) ? $extra : array();
$path = $field['path'];
$name = AnalystProfileFormTool::fieldName($path, $extra);
$id = AnalystProfileFormTool::fieldId($path, $extra);
$type = isset($field['type']) ? $field['type'] : 'string';
$value = isset($field['value']) ? $field['value'] : null;
$default = array_key_exists('default', $field) ? $field['default'] : null;

/*
 * A number that is stored is shown; one that is not shows nothing and
 * the placeholder says what the engine will use instead. Printing the
 * default into the box would store it on the next save and turn a
 * document that follows the shipped default into one that has frozen a
 * copy of it.
 */
$shown = $value === null ? '' : $value;
if (is_bool($shown)) {
    $shown = $shown ? 'true' : 'false';
}
/*
 * A field whose fallback is another setting carries its own
 * placeholder, because *what an empty box will use* is then a number
 * out of the document rather than the schema's word for it.
 */
$placeholder = '';
if ($value === null && isset($field['placeholder'])) {
    $placeholder = (string)$field['placeholder'];
} elseif ($value === null && $default !== null) {
    $placeholder = is_bool($default)
        ? ($default ? 'true' : 'false')
        : (string)$default;
}

$numeric = $type === 'float' || $type === 'int';
$classes = 'form-control form-control-sm';
if ($numeric) {
    $classes .= ' num text-end';
}

/*
 * A box that refuses a word as it is typed. `ValueSignalBase::checkMap()`
 * and `checkScalar()` already refuse one on save, but a setting that
 * looks like a number and takes `soon` is a round trip to learn what
 * the control could have said at the keystroke.
 *
 * **Unless what is stored is not a number.** A `number` input shows
 * nothing for a value it cannot parse, and a box that silently empties
 * itself posts the key away on the next save. Such a value is drawn as
 * text, where it stays visible and correctable.
 */
$asNumber = $numeric && ($shown === '' || is_numeric($shown));
$step = $type === 'int' ? '1' : 'any';

/*
 * How many characters a box holds, offered to whoever is laying it out.
 * A chip's control is a fixed `3.4rem` — right for a weight, wrong for
 * anything you have to finish reading — so it widens to this and the
 * section panes, where `.form-control` is already 100% of its cell,
 * ignore it.
 *
 * A custom property rather than `size`, which only text inputs honour:
 * the box that most needs the room here is a `number` whose placeholder
 * names what an empty one falls back to. Bounded both ways — a
 * one-character box is not a target, and an over-long stored value must
 * not push the table out.
 *
 * `types` and `state_map` hold arrays and draw their own controls,
 * so they never reach the box this sizes and must not be measured as
 * though they did.
 */
$chars = is_scalar($shown)
    ? max(4, min(28, max(
        mb_strlen((string)$shown),
        mb_strlen($placeholder)
    )))
    : 4;

/*
 * A number box is capped so a column of them lines up, and the cap
 * yields to a box that has more to say — the placeholder naming a
 * fallback is longer than any weight. Short contents never reach it,
 * so the section panes keep the width they had.
 */
$width = $numeric ? 'max(4.6rem, ' . (int)$chars . 'ch)' : '';
?>
<?php if ($type === 'bool'): ?>
    <?php if ($editable): ?>
        <input type="hidden" name="<?= h($name) ?>" value="false">
        <input class="form-check-input" type="checkbox"
               id="<?= h($id) ?>"
               name="<?= h($name) ?>" value="true"
               data-ap-field="1"
               data-ap-was="<?= !empty($value) ? 'true' : 'false' ?>"
               <?= !empty($value) ? 'checked' : '' ?>>
    <?php else: ?>
        <span class="wb-sub"><?= !empty($value)
            ? h(__('yes'))
            : h(__('no')) ?></span>
    <?php endif; ?>
<?php elseif ($type === 'select'): ?>
    <?php if ($editable): ?>
        <select class="form-select form-select-sm" id="<?= h($id) ?>"
                name="<?= h($name) ?>" data-ap-field="1"
                data-ap-was="<?= h((string)$shown) ?>"
                <?= empty($field['options']) ? 'disabled' : '' ?>>
            <?php foreach ($field['options'] as $option): ?>
                <?php
                $label = is_array($option)
                    ? (isset($option['label']) ? $option['label'] : $option['value'])
                    : $option;
                $optionValue = is_array($option) ? $option['value'] : $option;
                ?>
                <option value="<?= h($optionValue) ?>"
                    <?= (string)$optionValue === (string)$shown
                        ? 'selected' : '' ?>><?= h($label) ?></option>
            <?php endforeach; ?>
        </select>
    <?php else: ?>
        <?php
        /*
         * The label the picker would have shown, not the stored key.
         * The read-only viewer is where somebody decides whether to
         * fork a profile, and `most_common` there is the same
         * unexplained constant the editable pane stopped printing.
         */
        $readable = (string)$shown;
        foreach ($field['options'] as $option) {
            if (!is_array($option)
                || (string)$option['value'] !== (string)$shown
            ) {
                continue;
            }
            $readable = isset($option['label'])
                ? $option['label']
                : $option['value'];
            break;
        }
        ?>
        <span class="wb-id"><?= h($readable) ?></span>
    <?php endif; ?>
<?php elseif ($type === 'types'): ?>
    <?php
    /*
     * The types assigned to this bucket, and nothing else. MISP has
     * 194 attribute types and four buckets: drawing a control per type
     * per bucket is 776 of them, which is both the reason §4 says
     * *never a row per type MISP has* and, measured, 400KB of one
     * page. The picker beside them offers the types no bucket holds.
     *
     * **The row is read bucket-first and written type-first.** The
     * document stores `ttl_types` as type => bucket, and reading it
     * that way would put 194 rows on the page; the pane groups it the
     * other way round, so each chip posts itself back under its own
     * type with this bucket as the value. The block's `__present`
     * marker is what makes a chip taken off the page a key removed
     * from the map.
     */
    $held = is_array($value) ? $value : array();
    $taken = isset($field['taken']) ? $field['taken'] : array();
    $bucket = $field['key'];
    $mapPath = $field['path'];
    $free = array();
    foreach ($field['options'] as $option) {
        if (!isset($taken[$option])) {
            $free[] = $option;
        }
    }
    ?>
    <div class="ttl-chips" data-ap-chips="1">
        <?php foreach ($held as $option): ?>
            <span class="chip is-on">
                <?= h($option) ?>
                <?php if ($editable): ?>
                    <input type="hidden" data-ap-field="1"
                           data-ap-was="<?= h($bucket) ?>"
                           name="<?= h(AnalystProfileFormTool::fieldName(
                               $mapPath, array($option))) ?>"
                           value="<?= h($bucket) ?>">
                    <a href="#" class="ap-chip-drop"
                       aria-label="<?= h(sprintf(__('Remove %s'), $option)) ?>"
                       >&times;</a>
                <?php endif; ?>
            </span>
        <?php endforeach; ?>
        <?php if (empty($held)): ?>
            <span class="wb-sub"><?= h(__('nothing assigned')) ?></span>
        <?php endif; ?>
        <?php if ($editable): ?>
            <input class="chip-add" type="text"
                   list="<?= h(isset($datalist) ? $datalist : '') ?>"
                   data-ap-type-add="<?= h(
                       AnalystProfileFormTool::fieldName($mapPath)) ?>"
                   data-ap-type-value="<?= h($bucket) ?>"
                   placeholder="<?= h(sprintf(__n(
                       '+ add a type (%s unassigned)',
                       '+ add types (%s unassigned)',
                       count($free)
                   ), count($free))) ?>">
        <?php endif; ?>
    </div>
<?php elseif ($type === 'state_map'): ?>
    <?php
    /*
     * Three states per name, so a checklist will not do (D17): a
     * module can be ticked for a type, declared never, or left to the
     * default. `auto` is storable and not offered — the schema carries
     * it and the run path does not — so it appears only on a row whose
     * document already declares one, and a save keeps it.
     *
     * The names are the row's own: the modules block draws one row per
     * module and one select per attribute type that module accepts.
     */
    $states = is_array($value) ? $value : array();
    $built = isset($field['states_built'])
        ? $field['states_built']
        : array_map(function ($option) {
            return is_array($option) ? $option['value'] : $option;
        }, $field['state_options']);
    $unavailable = isset($field['unavailable']) ? $field['unavailable'] : array();
    /*
     * What the pill says about a name the row keeps but the instance
     * cannot honour. It is a different fact per block — a module this
     * instance does not enable, against a type this module does not
     * accept — and one hardcoded sentence could only ever be right in
     * one of them.
     */
    $goneLabel = isset($field['unavailable_label'])
        ? $field['unavailable_label']
        : __('not enabled here');
    /*
     * Past this many names the row stops being a list and becomes a
     * wall — `farsight_passivedns` accepts 21 attribute types. The
     * ones past the cap are rendered and hidden rather than dropped,
     * so they still post their stored state and a reader with no
     * JavaScript sees the whole row.
     */
    $collapseAfter = isset($field['collapse_after'])
        ? (int)$field['collapse_after']
        : 0;
    $collapses = $collapseAfter > 0
        && count($field['options']) > $collapseAfter;
    $shown = 0;
    ?>
    <div class="mod-states"<?= $collapses ? ' data-ap-collapse="1"' : '' ?>>
        <?php if ($editable): ?>
            <input type="hidden"
                   name="<?= h(AnalystProfileFormTool::fieldName($path,
                       array_merge($extra, array('__present')))) ?>"
                   value="1">
        <?php endif; ?>
        <?php
        /*
         * One control that writes every select below it. Most rows are
         * *this module, for everything it accepts* — six identical
         * choices for `circl_passivedns` — and there was no way to say
         * that except six times. It posts nothing itself: it is a
         * writer of the fields that do, which is why it carries no
         * `name` and is hidden until the page can drive it.
         */
        ?>
        <?php if ($editable && !empty($field['bulk_label'])
            && count($field['options']) > 1): ?>
            <div class="mod-row mod-bulk" hidden data-ap-bulk-wrap>
                <span class="wb-id"><?= h($field['bulk_label']) ?></span>
                <select class="form-select form-select-sm"
                        data-ap-bulk="1">
                    <option value="">&mdash;</option>
                    <?php foreach ($field['state_options'] as $option): ?>
                        <?php
                        $bulkValue = is_array($option)
                            ? $option['value']
                            : $option;
                        $bulkLabel = is_array($option)
                            && isset($option['label'])
                            ? $option['label']
                            : $bulkValue;
                        ?>
                        <option value="<?= h($bulkValue) ?>"
                            ><?= h($bulkLabel) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        <?php endif; ?>
        <?php foreach ($field['options'] as $rowName): ?>
            <?php
            $state = isset($states[$rowName]) ? $states[$rowName] : '';
            $gone = in_array($rowName, $unavailable, true);
            /*
             * A name the reader has an opinion about is never hidden,
             * whatever its position: collapsing a declared type would
             * hide the declaration itself.
             */
            $shown++;
            $folded = $collapses && $shown > $collapseAfter
                && $state === '' && !$gone;
            ?>
            <div class="mod-row <?= $gone ? 'is-off' : '' ?><?=
                $folded ? ' mod-folded' : '' ?>">
                <span class="wb-id" title="<?= h($rowName) ?>"><?=
                    h($rowName) ?></span>
                <?php if ($gone): ?>
                    <span class="pill t-missing"><?= h($goneLabel) ?></span>
                <?php endif; ?>
                <?php if ($editable): ?>
                    <?php
                    /*
                     * A state this document already holds is offered
                     * even where the editor no longer offers it to a
                     * new declaration. Without this the select would
                     * fall to its first option and the next save would
                     * rewrite a declaration nobody touched — `auto` is
                     * the case that exists, storable and not built.
                     */
                    $rowOptions = $field['state_options'];
                    $offered = array();
                    foreach ($rowOptions as $option) {
                        $offered[] = (string)(is_array($option)
                            ? $option['value']
                            : $option);
                    }
                    if ((string)$state !== ''
                        && !in_array((string)$state, $offered, true)
                    ) {
                        $rowOptions[] = array(
                            'value' => $state,
                            'label' => sprintf(
                                __('%s — kept from this profile'),
                                $state
                            ),
                        );
                    }
                    ?>
                    <select class="form-select form-select-sm"
                            data-ap-field="1"
                            data-ap-was="<?= h($state) ?>"
                            name="<?= h(AnalystProfileFormTool::fieldName(
                                $path,
                                array_merge($extra, array($rowName))
                            )) ?>">
                        <?php foreach ($rowOptions as $option): ?>
                            <?php
                            /*
                             * The blank is one of the options rather
                             * than a hardcoded first row: it is a
                             * state the document can be in, and what
                             * it resolves to is a thing the label has
                             * to be able to say.
                             */
                            $stateValue = is_array($option)
                                ? $option['value']
                                : $option;
                            $stateLabel = is_array($option)
                                && isset($option['label'])
                                ? $option['label']
                                : $stateValue;
                            $runs = $stateValue === ''
                                || in_array($stateValue, $built, true);
                            ?>
                            <option value="<?= h($stateValue) ?>"
                                <?= (string)$state === (string)$stateValue
                                    ? 'selected' : '' ?>
                                <?= $runs ? '' : 'data-ap-inert="1"' ?>
                                ><?= h($stateLabel) ?></option>
                        <?php endforeach; ?>
                    </select>
                <?php else: ?>
                    <?php
                    /*
                     * The label the picker would have shown. A reader
                     * deciding whether to fork a profile is owed the
                     * same wording as the analyst editing it.
                     */
                    $readableState = $state === ''
                        ? __('not declared')
                        : (string)$state;
                    foreach ($field['state_options'] as $option) {
                        if (is_array($option)
                            && (string)$option['value'] === (string)$state
                            && isset($option['label'])
                        ) {
                            $readableState = $option['label'];
                            break;
                        }
                    }
                    ?>
                    <span class="wb-sub"><?= h($readableState) ?></span>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
        <?php if ($collapses): ?>
            <button type="button" class="btn btn-link btn-sm mod-more"
                    hidden data-ap-more="1"
                    data-ap-more-less="<?= h(__('show fewer')) ?>"
                    data-ap-more-label="<?= h(sprintf(
                        __('show all %d types'),
                        count($field['options'])
                    )) ?>"></button>
        <?php endif; ?>
    </div>
<?php else: ?>
    <?php if ($editable): ?>
        <?php
        $style = '--fld-w:' . (int)$chars . 'ch';
        if ($width !== '') {
            $style .= ';max-width:' . $width;
        }
        $bounds = '';
        foreach (array('min', 'max') as $bound) {
            if ($asNumber && isset($field[$bound])) {
                $bounds .= ' ' . $bound . '="'
                    . h((string)$field[$bound]) . '"';
            }
        }
        ?>
        <input class="<?= h($classes) ?>"
               type="<?= $asNumber ? 'number' : 'text' ?>"
               <?= $asNumber ? 'step="' . h($step) . '"' : '' ?><?= $bounds ?>
               id="<?= h($id) ?>"
               name="<?= h($name) ?>"
               value="<?= h((string)$shown) ?>"
               data-ap-field="1"
               data-ap-was="<?= h((string)$shown) ?>"
               <?= $placeholder === ''
                   ? ''
                   : 'placeholder="' . h($placeholder) . '"' ?>
               style="<?= h($style) ?>">
    <?php else: ?>
        <span class="num"><?= $shown === ''
            ? '<span class="wb-sub">' . h(__('not set')) . '</span>'
            : h((string)$shown) ?></span>
    <?php endif; ?>
<?php endif; ?>
