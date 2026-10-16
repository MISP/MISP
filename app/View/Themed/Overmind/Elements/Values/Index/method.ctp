<?php
/**
 * The method note — what an assessment is.
 *
 * The one piece of prose on the page, and it is here rather than on
 * the profile because this is where somebody meeting the model for the
 * first time arrives. Three axes have to land before a chip reading
 * *Asserted threat* beside a number and the word *aging* parses as
 * anything at all (`value-index.md` §7.6).
 *
 * **It is a legend as well as a definition.** A row of the worklist
 * draws a lean chip, a band word and a relevance word, and a reader
 * who has just been told what the three axes ask still does not know
 * what answers they may give. So each axis carries its own vocabulary,
 * in the chrome the rows use — the same chip, the same colour, the
 * same quiet treatment for the leans that name no state.
 *
 * **Every word of that vocabulary is read from the engine, never
 * transcribed.** A note listing four leans a fifth release has made
 * five is worse than no note: it is the page teaching a reader a model
 * the engine has stopped holding, and nothing would fail to say so.
 * `ValueLean::TREATMENTS`, `ValueRelevanceTool::STATES` and
 * `ValueVerdictTool::BANDS` are the three sources, and adding a state
 * to any of them adds it here.
 *
 * **A real `<details>`, so it works with no script.** The script's
 * only job is to remember which way this reader left it, which is a
 * per-viewer convenience and lives in `localStorage` — nothing about a
 * value, visible to nobody else, and a store that comes back empty
 * simply gives the default (§7.6).
 *
 * It sits in the conditions strip as its last occupant, so the
 * sentences that say under what rules the session is worked keep the
 * first line and the note takes a line of its own when it is opened.
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
App::uses('ValueVerdictTool', 'Tools/ValueIntelligence');

/*
 * The leans, drawn exactly as `assessment.ctp` draws the one on a
 * row: a solid chip for the two that name a state, and a hollow mark
 * and no ground for the ones that refuse to. A loud chip reading
 * *Contested* in a legend teaches the wrong thing twice over.
 */
$leans = array();
foreach (array_keys(ValueLean::TREATMENTS) as $lean) {
    $leans[] = '<span class="vi-lean vi-lean--' . h(ValueLean::slug($lean))
        . '">' . ValueLean::quietMark($lean)
        . h(ValueLean::label($lean)) . '</span>';
}

/*
 * The relevance words come through `stateLabel()` rather than out of a
 * fourth copy of the same four strings. That accessor exists because
 * the copies had already drifted once — one surface printed
 * `uncertain` raw where the others said *timeline uncertain* — and a
 * legend that disagreed with the rows it explains would be the worst
 * place yet for that to happen.
 */
$relevances = array();
foreach (ValueRelevanceTool::STATES as $state) {
    $relevances[] = '<span class="vi-relword vi-rel--' . h($state) . '">'
        . h(ValueRelevanceTool::stateLabel($state)) . '</span>';
}

/*
 * The bands, weakest first, which is the order the constant holds them
 * in and the order a reader reads a scale in. `none` is one of the
 * four and is listed: it is what a record with nothing to weigh gets,
 * and a legend that quietly dropped it would leave the one band a new
 * instance actually shows unexplained.
 */
$bands = array();
foreach (ValueVerdictTool::BANDS as $band) {
    $bands[] = '<span class="vi-axband">' . h($band) . '</span>';
}

$axes = array(
    array(
        'axis' => __('Lean'),
        'question' => __('What does the data in MISP say this value is?'),
        'words' => implode(' ', $leans),
    ),
    array(
        'axis' => __('Relevance'),
        'question' => __('Is it still relevant today?'),
        'words' => implode(' ', $relevances),
    ),
    array(
        'axis' => __('Signal strength'),
        'question' => __('How much weight does the evidence carry?'),
        'words' => implode(' ', $bands),
    ),
);
?>
<details class="vi-note" data-vi-note>
    <summary>
        <svg class="vi-note__chev" width="10" height="10"
             viewBox="0 0 10 10" aria-hidden="true"><path d="M3 1.5 7 5l-4 3.5"
             fill="none" stroke="currentColor" stroke-width="1.5"
             stroke-linecap="round" stroke-linejoin="round"/></svg>
        <?= h(__('How assessments work')) ?>
    </summary>
    <div class="vi-note__body">
        <table class="vi-axes">
            <tbody>
<?php foreach ($axes as $axis): ?>
                <tr>
                    <th scope="row"><?= h($axis['axis']) ?></th>
                    <td>
                        <span class="vi-axq"><?= h($axis['question']) ?></span>
                        <span class="vi-axv"><?= $axis['words'] ?></span>
                    </td>
                </tr>
<?php endforeach; ?>
            </tbody>
        </table>
        <p><?= h(__(
            'None of these says whether a value is malicious. They'
            . ' describe what MISP has recorded about it: which'
            . ' organisations reported it, how often, how recently and'
            . ' whether they agree.'
        )) ?></p>
    </div>
</details>
