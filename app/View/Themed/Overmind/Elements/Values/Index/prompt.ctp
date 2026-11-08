<?php
/**
 * The prompt — one box in the index filter bar's look, and the verb for
 * what pressing it does: the live `n/100` counter, the verb that says
 * what pressing will do, and Clear beside them, because what it undoes is
 * what the rest of the line did.
 *
 * The counter and the verb are rendered at their empty-box values and
 * moved by `value-index.js` from there. A box that comes back filled
 * after a submission is the case that makes this matter: the server
 * renders `0/100` and *Open profile*, and the script corrects both
 * before the reader can read either, because it runs on
 * `DOMContentLoaded` against the value already in the field.
 *
 * The form is built through `FormHelper` rather than by hand because
 * `SecurityComponent` hashes the fields it emits: a raw `<textarea>`
 * with the right name posts to a blackhole.
 *
 * The textarea refills itself from `$this->request->data`, which is
 * the whole of *the box keeps its content* (§8 G11) — a reader fixing
 * one character does not re-type the value.
 *
 * Beside the box is the one question about it: whether what was pasted
 * is a list of values or a text with values in it (§11). At the end of
 * the bar, the analyst profile its answers are worked under.
 */
App::uses('ValueInputTool', 'Tools/ValueIntelligence');

echo $this->Form->create('Value', array(
    'class' => 'vi-prompt ifp-bar d-flex flex-wrap align-items-start',
    'id' => 'vi-prompt',
    'url' => $this->Html->url(array(
        'controller' => 'values',
        'action' => 'resolve',
    )),
    /*
     * The second destination, on the form rather than in the script:
     * a URL built by `Html->url()` is right under a subdirectory
     * install and a string in a `.js` file is not.
     */
    'data-vi-triage' => $this->Html->url(array(
        'controller' => 'values',
        'action' => 'triage',
    )),
));
?>
    <?php
    /*
     * The filter bar's search box, holding a textarea: one line until a
     * list is pasted, then as tall as the list (value-index.js).
     */
    ?>
    <label class="vi-prompt__field ifp-query vi-query">
        <i class="fas fa-arrow-right-to-bracket ifp-q-icon" aria-hidden="true"></i>
        <?= $this->Form->textarea('value', array(
            'class' => 'vi-ta',
            'rows' => 1,
            'autofocus' => true,
            'spellcheck' => 'false',
            'autocomplete' => 'off',
            'autocapitalize' => 'off',
            'aria-keyshortcuts' => '/',
            'data-vi-box' => '1',
            'placeholder' => __('Paste a value or a list of values; defanged input is refanged'),
            'aria-label' => __('Values to look up'),
        )) ?>
        <span class="ifp-q-end">
            <span class="vi-count" data-vi-count
                  data-vi-cap="<?= h(ValueInputTool::CAP) ?>"
                  aria-live="polite"><b>0</b>/<?= h(ValueInputTool::CAP) ?></span>
            <?php
            /*
             * Clear. It empties the box and puts the region back to the
             * invitation, which is the state a reload would reach without
             * re-reading the figures and the carried-over list, none of
             * which the reader's paste changed.
             *
             * **It is `hidden` until there is something to clear**, so the
             * empty page is not offering to empty itself, and it starts
             * that way in the markup rather than being hidden by the
             * script: a page whose script never boots shows a button that
             * does nothing otherwise.
             *
             * **It does not touch the carried-over list.** That list is
             * this reader's history rather than this session's work, and
             * emptying it is `value-index.md` §10's own item.
             */
            ?>
            <button type="button" class="vi-wipe"
                    data-vi-clear
                    data-vi-ask="<?= h(__('Clear anyway?')) ?>"
                    title="<?= h(__('Clear (Esc)')) ?>"
                    hidden>
                <span data-vi-clear-verb><?= h(__('Clear')) ?></span>
            </button>
            <button type="submit" class="ifp-q-go vi-run" data-vi-go="1" data-tour="values-run">
                <?php
                /*
                 * Both wordings travel with the markup rather than living
                 * in the script, so the verb is translated by the same
                 * catalogue as everything else on the page.
                 */
                ?>
                <span aria-hidden="true">↵</span>
                <span data-vi-verb
                      data-vi-one="<?= h(__('Open intelligence')) ?>"
                      data-vi-many="<?= h(__('Look up %d values')) ?>"
                      data-vi-find="<?= h(__('Extract values')) ?>"
                      ><?= h(__('Open intelligence')) ?></span>
            </button>
            <kbd class="ifp-q-kbd" title="<?= h(__('Press / to look up')) ?>">/</kbd>
        </span>
    </label>
    <div class="vi-prompt__side">
        <?php
        /*
         * The one question about the paste, as a toggle beside the box.
         *
         * **Off every time, and nothing remembers it**
         * (`value-index.md` §11, V20). Only the reader knows whether
         * what they just pasted is a list of values or a report with
         * values in it, and the next paste is as likely to be the
         * other kind — so a remembered answer would be the page
         * deciding, once, on behalf of every paste after it.
         *
         * `FormHelper` emits its own hidden field before the box, so
         * an unchecked press posts `0` rather than nothing, and
         * `SecurityComponent` sees the field set it hashed. The
         * `checked` state is given explicitly: a submission that comes
         * back with the box refilled must come back with the mode the
         * reader chose, or their next press would silently change the
         * question.
         */
        ?>
        <label class="ifp-fbtn vi-mode" title="<?= h(__(
            'Use this for a pasted report or advisory. When off,'
            . ' each line is looked up as one value.'
        )) ?>">
            <?= $this->Form->checkbox('extract', array(
                'value' => 1,
                'class' => 'visually-hidden',
                'checked' => !empty(
                    $this->request->data['Value']['extract']
                ),
                'data-vi-extract' => '1',
            )) ?>
            <i class="fas fa-file-lines" aria-hidden="true"></i>
            <span><?= h(__('Extract from text')) ?></span>
        </label>
    </div>
    <div class="ifp-end">
        <?= $this->element('Values/Index/conditions', array(
            'inForce' => $inForce,
        )) ?>
    </div>
<?= $this->Form->end() ?>
