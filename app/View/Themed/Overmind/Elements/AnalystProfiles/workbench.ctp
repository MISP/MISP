<?php
/**
 * The editor: the document on the left, the value under assessment on
 * the right.
 *
 * The right-hand pane is the bet. It never leaves, so changing a
 * weight and not looking at what it did is not a thing the page lets
 * you do — which is the one property that separates this from the
 * simulator MISP already shipped and nobody used.
 *
 * `view` renders the same two panes with `editable` false: a profile
 * somebody else owns reads exactly as your own does, minus the inputs.
 *
 * @var array $profile
 * @var bool $editable
 * @var array $sections
 * @var array $groups
 * @var array $bands
 * @var array $errors
 * @var array $warnings
 * @var array $legacy
 * @var array $loader_errors
 * @var string $raw
 * @var string|null $value
 * @var array $bench
 * @var string|null $open_section
 * @var array|null $parse A refused paste, with its line
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$detail = $bench['detail'];
$ledger = array();
if ($detail !== null) {
    foreach ($detail['rows'] as $row) {
        if ($row['after'] !== null) {
            $ledger[$row['id']] = $row['after'];
        }
    }
}
$runway = $detail !== null && isset($detail['axes']['relevance']['runway'])
    ? $detail['axes']['relevance']['runway']
    : null;
$marks = $detail === null
    ? array()
    : array(
        'was' => $detail['totals']['before'],
        'now' => $detail['totals']['after'],
    );
/*
 * The direction pair is *with* and *against the lean*, not red and
 * green: on a benign record the row that agrees with the lean is the
 * green one. Both halves of this page colour contributions, so both are
 * handed the same lean — the bench re-emits it on every recompute,
 * because editing a weight can flip the lean itself.
 */
$lean = $detail !== null && isset($detail['axes']['lean']['after'])
    ? $detail['axes']['lean']['after']
    : null;

$open = $open_section !== null ? $open_section : 'signals';
$parse = isset($parse) ? $parse : null;
?>
<div class="ap-page">
    <div class="container-fluid">
        <?= $this->element('AnalystProfiles/loader_errors', array(
            'loader_errors' => $loader_errors,
        )) ?>

        <?php foreach ($errors as $error): ?>
            <div class="wb-note bad mb-2"><?= h($error) ?></div>
        <?php endforeach; ?>
        <?php foreach ($warnings as $warning): ?>
            <div class="wb-note warn mb-2"><?= h($warning) ?></div>
        <?php endforeach; ?>
        <?php foreach ($legacy as $note): ?>
            <div class="wb-note mb-2">
                <b><?= h(__('Written by an older version.')) ?></b>
                <?= h($note) ?>
            </div>
        <?php endforeach; ?>

        <?= $this->Form->create('AnalystProfile', array(
            'id' => 'ap-form',
            /*
             * No `?value=` on it. The value under assessment rides in
             * the hidden field below, which the recompute posts — one
             * place to change when the bench is handed another value,
             * and `__requestedValue()` prefers the query when there is
             * one, so a query here would pin the bench to whatever the
             * page loaded with.
             */
            'data-ap-simulate' => $this->Html->url(array(
                'action' => 'simulate',
                $profile['id'],
            )),
            /*
             * The URL as a string, from the same helper every link on
             * the page uses. `Form->create` given an array underscores
             * the controller — `/analyst_profiles/edit/23` — which
             * routes but is not the URL anything else on the instance
             * writes, and a form posting to a second spelling of its
             * own controller is how one of them stops being tested.
             */
            'url' => $this->Html->url(array(
                'action' => 'edit',
                $profile['id'],
                '?' => $value === null
                    ? array()
                    : array('value' => ValueUrlTool::encode($value)),
            )),
        )) ?>
            <input type="hidden" id="ap-bench-value"
                   name="data[AnalystProfile][value]"
                   value="<?= $value === null
                       ? '' : h(ValueUrlTool::encode($value)) ?>">
            <div class="wb">
                <div class="wb-panehead wb-panehead-left">
                    <span><?= h(__('The profile')) ?></span>
                    <em><?= h(sprintf(__('%s sections · one open'),
                        count($sections) + 1)) ?></em>
                </div>
                <div class="wb-panehead wb-panehead-right">
                    <span><?= h(__('The value under assessment')) ?></span>
                    <em><?= h($editable
                        ? __('recomputed on every change')
                        : __('scored under this profile')) ?></em>
                </div>

                <?= $this->element('AnalystProfiles/rail', array(
                    'sections' => $sections,
                    'groups' => $groups,
                    'open' => $open,
                    'raw' => $raw,
                    'editable' => $editable,
                )) ?>

                <div class="wb-body">
                    <?php foreach ($sections as $id => $section): ?>
                        <?= $this->element('AnalystProfiles/section', array(
                            'section' => $section,
                            'editable' => $editable,
                            'open' => $open === $id,
                            'ledger' => $ledger,
                            'benchValue' => $value,
                            'marks' => $marks,
                            'runway' => $runway,
                            'lean' => $lean,
                        )) ?>
                    <?php endforeach; ?>

                    <section class="wb-sec <?= $open === 'raw' ? 'is-open' : '' ?>"
                             data-sec="raw">
                        <p class="wb-h"><?= h(__('Raw JSON')) ?>
                            <span class="wb-ax"><?= h(__('all three')) ?></span>
                        </p>
                        <p class="wb-blurb">
                            <?= h($editable
                                ? __('The whole document. Pasting one'
                                    . ' replaces it — nothing is merged.')
                                : __('The whole document.')) ?>
                        </p>
                        <?php if (!empty($parse)): ?>
                            <div class="wb-note bad mb-2">
                                <b><?= h(__('Not saved.')) ?></b>
                                <?= h($parse['error']) ?>
                                <?php if ($parse['line'] !== null): ?>
                                    <?= h(sprintf(__('Line %s.'), $parse['line'])) ?>
                                <?php endif; ?>
                                <div class="wb-sub mt-1">
                                    <?= h(__('The box below holds what you'
                                        . ' posted.')) ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        <?php
                        /*
                         * Disabled unless this is the pane that is open,
                         * and a disabled field posts nothing.
                         *
                         * Without that, saving any other section would
                         * also post the whole document — and `edit`
                         * prefers a pasted document over a merged
                         * section, so every save would silently replace
                         * the edit with whatever the box last held. The
                         * rail re-enables it on the way in.
                         */
                        ?>
                        <textarea class="form-control font-monospace"
                                  id="ap-raw" rows="24" spellcheck="false"
                                  name="data[AnalystProfile][parameters_json]"
                                  <?= $open === 'raw' ? '' : 'disabled' ?>
                                  <?= $editable ? '' : 'readonly' ?>><?= h($raw) ?></textarea>
                        <?php if ($editable): ?>
                            <button type="submit"
                                    class="btn btn-sm btn-primary mt-2">
                                <?= h(__('Replace the document')) ?>
                            </button>
                            <span class="wb-sub ms-2">
                                <?= h(__('If the JSON will not parse,'
                                    . ' nothing is saved.')) ?>
                            </span>
                        <?php endif; ?>
                    </section>
                </div>

                <aside class="wb-bench">
                    <?= $this->element('AnalystProfiles/bench', array(
                        'bench' => $bench,
                        'bands' => $bands,
                        'full' => false,
                        'profileId' => $profile['id'],
                    )) ?>
                </aside>
            </div>
        <?= $this->Form->end() ?>
    </div>
</div>
