<?php
/**
 * What has been said about this value, in the order it was said.
 *
 * One chronological thread rather than separate lists, because a reply
 * has to sit next to what it replies to: MISP lets a note carry a note
 * and an opinion carry an opinion two levels deep, and a feed grouped
 * by kind turns that conversation into unrelated fragments.
 *
 * **Proposals are here too, since phase 26.** A proposal is how MISP
 * let a third party disagree before analyst data existed, and this
 * panel's subject is who says what about the value
 * (`value-intelligence-coverage.md` §5) — so the choice was to include them
 * or to exclude them *in words*, and silently omitting them was the one
 * option that left the panel claiming a completeness it did not have.
 * They are drawn, filtered by their own pill, and they reach neither
 * the aggregate nor the ledger: a proposal is a change somebody wants
 * made to a row, not a position on the value.
 *
 * Three things this panel refuses to fake:
 *
 * - **What an item hangs off.** Analyst data attaches to an
 *   `object_uuid` and an `object_type`, never to a value. Every item
 *   carries a chip naming its real target, and an event-level item says
 *   that it is inherited by every occurrence in that event rather than
 *   said about this value.
 * - **What an opinion rates.** An opinion written on a note rates the
 *   note. It takes no side on the value and is excluded from the
 *   standing panel's aggregate, and it says so inline.
 * - **Where MISP stops.** The thread nests two levels. The endpoint
 *   reads one level past the last one drawn, so the second level's
 *   *flagged but not fetched* line is a measurement rather than an
 *   assumption.
 *
 * Markdown is rendered here. MISP stores it and renders none of it
 * today — `Analyst_data/thread.ctp` prints notes `pre-line` with no
 * parser — so this is a decision the tab is making, and one that would
 * apply to every note on the instance because there is no per-note
 * markup flag (`05-analyst.md` §11).
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewAnalystThread.
 *
 * @var array $valueIntelligence
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
$analyst = $valueIntelligence['analyst'];
$thread = $analyst['thread'];
$counts = $analyst['counts'];
$stats = $valueIntelligence['occurrence_stats'];

/**
 * MISP's distribution levels, as the words the rest of the product
 * uses for them.
 *
 * @param int $level
 * @param string|null $sharingGroup
 * @return array label, icon
 */
$distribution = function ($level, $sharingGroup) {
    $levels = array(
        0 => array(__('Your organisation only'), 'fas fa-lock'),
        1 => array(__('This community only'), 'fas fa-share-nodes'),
        2 => array(__('Connected communities'), 'fas fa-share-nodes'),
        3 => array(__('All communities'), 'fas fa-share-nodes'),
    );
    if ((int)$level === 4) {
        return array(
            $sharingGroup === null ? __('Sharing group') : $sharingGroup,
            'misp-icon misp-icon-sharing-group misp-simple',
        );
    }
    return isset($levels[(int)$level])
        ? $levels[(int)$level]
        : array(__('Inherit event'), 'fas fa-share-nodes');
};

/**
 * A very small markdown subset: headings, bullets, block quotes,
 * paragraphs, inline code and bold.
 *
 * Escaped first and marked up afterwards, so a note that contains
 * `<script>` is a note that contains the characters `<script>`. That
 * ordering is the whole safety argument — there is no sanitiser here
 * and none is needed, because no author-supplied byte ever reaches the
 * output unescaped.
 *
 * @param string $text
 * @return string
 */
$markdown = function ($text) {
    $inline = function ($line) {
        $line = h($line);
        $line = preg_replace('/`([^`]+)`/', '<code>$1</code>', $line);
        $line = preg_replace(
            '/\*\*([^*]+)\*\*/',
            '<strong>$1</strong>',
            $line
        );
        return $line;
    };

    $out = '';
    $para = array();
    $list = array();
    $quote = array();

    $flush = function () use (&$out, &$para, &$list, &$quote, $inline) {
        if (!empty($list)) {
            $out .= '<ul>';
            foreach ($list as $item) {
                $out .= '<li>' . $inline($item) . '</li>';
            }
            $out .= '</ul>';
            $list = array();
        }
        if (!empty($quote)) {
            $out .= '<blockquote>' . $inline(implode(' ', $quote))
                . '</blockquote>';
            $quote = array();
        }
        if (!empty($para)) {
            $out .= '<p class="mb-0">' . $inline(implode(' ', $para))
                . '</p>';
            $para = array();
        }
    };

    foreach (preg_split('/\R/', trim($text)) as $line) {
        $line = rtrim($line);
        if ($line === '') {
            $flush();
            continue;
        }
        if (preg_match('/^#{1,6}\s+(.*)$/', $line, $m)) {
            $flush();
            $out .= '<h4>' . $inline($m[1]) . '</h4>';
            continue;
        }
        if (preg_match('/^[-*]\s+(.*)$/', $line, $m)) {
            if (!empty($para) || !empty($quote)) {
                $flush();
            }
            $list[] = $m[1];
            continue;
        }
        if (preg_match('/^>\s?(.*)$/', $line, $m)) {
            if (!empty($para) || !empty($list)) {
                $flush();
            }
            $quote[] = $m[1];
            continue;
        }
        if (!empty($list) || !empty($quote)) {
            $flush();
        }
        $para[] = $line;
    }
    $flush();

    return $out;
};

/**
 * Whether a body actually uses any of the markup the renderer knows
 * about. The chip is a statement about this note, so a plain sentence
 * does not get to claim it was rendered from markdown.
 *
 * @param string $text
 * @return bool
 */
$isMarkdown = function ($text) {
    return (bool)preg_match('/(^|\R)\s*(#{1,6}\s|[-*]\s|>\s)|`|\*\*/', $text);
};

/**
 * The chip naming what an item hangs off — and opening it.
 *
 * **Every chip that names a record is a link to that record**, which is
 * the rule phase 25 settled for the Timeline and phase 26 applied here
 * afterwards: naming `#177` and leaving the reader to find it is the
 * page knowing an address and keeping it. The two that are not links
 * are the two with nowhere to go — a reply, whose parent is drawn
 * directly above it, and a target that no longer resolves.
 *
 * Event, object and attribute all open the event, because that is where
 * MISP renders all three; the anchor picks the tab. A cluster opens its
 * own page, at the address three other panels on this page already use.
 *
 * @param array $target
 * @return string
 */
$attachChip = function ($target) use ($baseurl) {
    $event = isset($target['event'])
        ? '#' . $target['event']
        : __('an event');
    $eventUrl = empty($target['event'])
        ? null
        : $baseurl . '/events/view/' . (int)$target['event'];

    /*
     * One emitter for every branch, so a chip cannot become a link in
     * one arm and stay inert in another by omission.
     */
    $chip = function ($href, $title, $body, $extra = '') {
        $class = 'vpa-chip' . $extra . ($href === null ? '' : ' vpa-chip-link');
        if ($href === null) {
            return '<span class="' . $class . '" title="' . h($title)
                . '">' . $body . '</span>';
        }
        return '<a class="' . $class . '" href="' . h($href)
            . '" title="' . h($title) . '">' . $body
            . '<i class="fas fa-arrow-up-right-from-square"
                  aria-hidden="true"></i></a>';
    };

    // Written on the value itself; another spelling opens that spelling's page
    if ($target['kind'] === 'value') {
        if ($target['spelled'] === null) {
            return $chip(
                null,
                __('Written on this value itself, not on one of its occurrences.'),
                '<i class="fas fa-fingerprint" aria-hidden="true"></i>'
                    . h(__('this value'))
            );
        }
        return $chip(
            $baseurl . '/values/view/' . ValueUrlTool::encode($target['spelled']),
            __('Written on this value in another spelling. Opens that spelling.'),
            '<i class="fas fa-fingerprint" aria-hidden="true"></i>'
                . h(__('this value'))
                . '<span class="vpa-chip-sep">' . h(__('spelled')) . '</span>'
                . h($target['spelled'])
        );
    }

    if ($target['kind'] === 'event') {
        return $chip(
            $eventUrl,
            __(
                'Attached to the event, so it is inherited by every'
                . ' occurrence in it. Opens the event.'
            ),
            '<span class="misp-icon misp-icon-event misp-simple"></span>'
                . h($event)
                . '<span class="vpa-chip-sep">' . h(__('inherited'))
                . '</span>'
        );
    }

    if ($target['kind'] === 'object') {
        return $chip(
            $eventUrl === null ? null : $eventUrl . '#tab-objects',
            __(
                'Attached to the object the occurrence sits in. Opens'
                . ' the event, on its Objects tab.'
            ),
            '<span class="misp-icon misp-icon-object misp-simple"></span>'
                . h($target['name'])
                . '<span class="vpa-chip-sep">' . h(__('in')) . '</span>'
                . '<span class="misp-icon misp-icon-event misp-simple">'
                . '</span>' . h($event)
        );
    }

    if ($target['kind'] === 'reply') {
        /*
         * `reply` carries which kind it answers, because a reply to an
         * opinion is not a reply to a note and the chip is the one
         * place that says what the row hangs off.
         *
         * Not a link: the item it names is the one immediately above
         * it, already on the reader's screen.
         */
        $to = isset($target['to']) && $target['to'] === 'opinion'
            ? __('the opinion above')
            : __('the note above');
        return $chip(
            null,
            __(
                'Attached to the item above, which is what makes it a'
                . ' statement about that item rather than about the'
                . ' value'
            ),
            '<span class="misp-icon misp-icon-analyst-note'
                . ' misp-simple"></span>' . h($to)
        );
    }

    /*
     * A galaxy cluster the value is classified under. Analyst data
     * attaches to a cluster's uuid like anything else, and phase 24's
     * claim reader already counts a plain galaxy *tag* on the same
     * events — so counting the tag and dropping an authored statement
     * about the cluster was the omission `26-analyst.md` D1 closes.
     */
    if ($target['kind'] === 'cluster') {
        return $chip(
            empty($target['id'])
                ? null
                : $baseurl . '/galaxy_clusters/view/' . (int)$target['id'],
            __(
                'Attached to a galaxy cluster this value is classified'
                . ' under, so it is inherited by everything else'
                . ' carrying that cluster. Opens the cluster.'
            ),
            '<span class="misp-icon misp-icon-galaxy misp-simple"></span>'
                . h($target['name'])
                . '<span class="vpa-chip-sep">' . h(__('cluster'))
                . '</span>'
        );
    }

    /*
     * The row is drawn anyway. One `notes` row on the verification
     * instance carries an `object_type` that is not a type and an
     * `object_uuid` that resolves to nothing — MISP's own UI wrote it —
     * and dropping such a row would let a write the instance accepted
     * vanish from the one page whose subject is who said what.
     * `26-analyst.md` D5. Nowhere to link, which is the whole point.
     */
    if ($target['kind'] === 'unresolved') {
        return $chip(
            null,
            __(
                'This item names a target that no longer resolves to an'
                . ' attribute, event, object or cluster. It is shown'
                . ' because somebody wrote it, not because it still'
                . ' points anywhere.'
            ),
            '<i class="fas fa-link-slash"></i>'
                . h(__('target does not resolve')),
            ' vpa-chip-unresolved'
        );
    }

    return $chip(
        $eventUrl === null ? null : $eventUrl . '#tab-attributes',
        __(
            'Analyst data attaches to an object_uuid, never to a value —'
            . ' this item hangs off one attribute occurrence. Opens the'
            . ' event, on its Attributes tab.'
        ),
        '<span class="misp-icon misp-icon-attribute misp-simple"></span>'
            . h($target['type'])
            . '<span class="vpa-chip-sep">' . h(__('in')) . '</span>'
            . '<span class="misp-icon misp-icon-event misp-simple"></span>'
            . h($event)
    );
};

$readsBadge = function ($reads) {
    if ($reads === 'malicious') {
        return 'success';
    }
    if ($reads === 'benign') {
        return 'danger';
    }
    return 'secondary';
};

/**
 * An opinion's score, drawn beside the number.
 *
 * `82/100` is exact and says nothing about where 82 sits. The scale is
 * the standing panel's lane at thread scale — a pivot at 50, a bar
 * growing from it toward the score — so the same encoding carries the
 * same meaning on both panels: direction is the side, length is the
 * conviction.
 *
 * Deliberately not a left-anchored fill. That would read as "magnitude
 * from zero" about a number whose whole meaning is which side of 50 it
 * falls on, and would make 45 and 55 look nearly identical rather than
 * opposed.
 *
 * The hue is inherited: the item's own `.vpa-side-*` class sets
 * `--vpa-side`, and an opinion that rates a note carries the neutral
 * one, so its scale is grey without this closure knowing why.
 *
 * Hidden from assistive technology — the badge beside it already states
 * the label and the score, and a second announcement of the same number
 * is noise.
 *
 * @param int $score
 * @return string
 */
$opinionScale = function ($score) {
    $score = max(0, min(100, (int)$score));
    $from = min(50, $score);
    $to = max(50, $score);
    if ($score > 50) {
        $note = __('%d/100 — above the 50 pivot, agreeing');
    } elseif ($score < 50) {
        $note = __('%d/100 — below the 50 pivot, disputing');
    } else {
        $note = __('%d/100 — on the pivot, arguing neither way');
    }
    return '<span class="vpa-scale" aria-hidden="true" title="'
        . h(sprintf($note, $score)) . '">'
        . '<span class="vpa-scale-track"></span>'
        . '<span class="vpa-scale-pivot"></span>'
        . '<span class="vpa-scale-bar" style="left: ' . $from
        . '%; right: ' . (100 - $to) . '%;"></span>'
        . '<span class="vpa-scale-dot" style="left: ' . $score
        . '%;"></span>'
        . '</span>';
};

/*
 * One item and everything written under it. Recursive, because the
 * shape is: MISP returns two levels and the template renders exactly
 * what it was given rather than flattening it into a list with an
 * indent column.
 */
$renderItem = function ($item, $depth) use (
    &$renderItem,
    $markdown,
    $isMarkdown,
    $attachChip,
    $distribution,
    $readsBadge,
    $opinionScale,
    $baseurl
) {
    $isOpinion = $item['kind'] === 'opinion';
    $isProposal = $item['kind'] === 'proposal';
    /*
     * A proposal argues about a *row*, not about the value, so it is
     * neither counted nor marked as one that was excluded — the
     * "not in the aggregate" note belongs to opinions that could have
     * been in it. Its own chips say what it is.
     */
    $ratesNote = !$isProposal && $item['rates'] !== 'value';
    list($distLabel, $distIcon) = $distribution(
        $item['distribution'],
        $item['sharing_group']
    );
    $side = 'vpa-side-none';
    if ($item['reads'] === 'malicious') {
        $side = 'vpa-side-agree';
    } elseif ($item['reads'] === 'benign') {
        $side = 'vpa-side-disagree';
    }

    $kind = 'note';
    if ($isOpinion) {
        $kind = 'opinion';
    } elseif ($isProposal) {
        $kind = 'proposal';
    }
    /*
     * **A short plain sentence shares the line with its own badges.**
     * The item was three stacked lines — the badge row, the body, the
     * meta — and on four of `8.8.8.8`'s seven items the middle one held
     * a sentence of four words under a badge reading `Agree · 80/100`.
     * Beside it the two read as one statement, which is what they are,
     * and the item loses 22px.
     *
     * Only when it is genuinely one line of prose. `$isMarkdown` is
     * already the panel's test for a body the renderer will turn into
     * headings, bullets or a quote, and a block element does not belong
     * inside a flex row of badges; the length bound catches the plain
     * paragraph long enough to want the full width anyway. A proposal
     * is excluded outright — its first row is the change strip, which
     * is a block by design.
     */
    $inlineBody = !$isProposal
        && $item['body'] !== ''
        && !$isMarkdown($item['body'])
        && mb_strlen($item['body']) <= 120;
    $out = '<div class="vp-analyst vp-analyst-' . $kind . ' ' . $side
        . '">';

    $out .= '<div class="vp-analyst-kind">'
        . ($isProposal
            ? '<i class="fas fa-code-pull-request"></i>'
            : '<span class="misp-icon misp-icon-analyst-'
                . ($isOpinion ? 'opinion' : 'note')
                . ' misp-simple"></span>')
        . h($isProposal
            ? __('Proposal')
            : ($isOpinion ? __('Opinion') : __('Note')))
        . '</div>';

    $out .= '<div class="vp-analyst-body">';

    $out .= '<div class="d-flex align-items-center gap-2 mb-1 flex-wrap">';
    if ($isOpinion) {
        $colour = $ratesNote ? 'secondary' : $readsBadge($item['reads']);
        $out .= '<span class="badge bg-' . $colour . '-subtle text-'
            . $colour . '-emphasis border border-' . $colour
            . '-subtle fw-semibold">' . h($item['label'])
            . ' &middot; ' . h($item['score']) . '/100</span>'
            . $opinionScale($item['score']);
    } elseif ($isProposal) {
        /*
         * **Open or resolved, and never accepted or discarded.**
         * `ShadowAttribute::setDeleted` is what both the accept path
         * and the discard path end at, and it writes one `deleted`
         * column. The schema that would tell the two apart does not
         * exist, so the chip states what MISP recorded and stops.
         */
        $resolved = !empty($item['proposal']['resolved']);
        $out .= '<span class="badge bg-'
            . ($resolved ? 'secondary' : 'warning')
            . '-subtle text-' . ($resolved ? 'secondary' : 'warning')
            . '-emphasis border border-'
            . ($resolved ? 'secondary' : 'warning')
            . '-subtle fw-semibold" title="'
            . h($resolved
                ? __(
                    'Closed. MISP records only that it closed —'
                    . ' accepting and discarding a proposal both write'
                    . ' the same column.'
                )
                : __('Nobody has accepted or discarded this yet.'))
            . '">' . h($resolved ? __('Resolved') : __('Open'))
            . '</span>';
    } elseif ($isMarkdown($item['body'])) {
        $out .= '<span class="vpa-chip" title="'
            . h(__(
                'MISP stores this body as written and renders none of'
                . ' it today. This page renders it.'
            )) . '"><i class="fas fa-align-left me-1"></i>'
            . h(__('rendered from markdown')) . '</span>';
    }
    if ($ratesNote) {
        $unresolved = $item['attached_to']['kind'] === 'unresolved';
        $out .= '<span class="vpa-notcounted">'
            . '<i class="fas fa-circle-info"></i>'
            . h($unresolved
                ? __(
                    'the row this hangs off does not resolve — not in'
                    . ' the aggregate'
                )
                : __(
                    'about the item above, not about the value — not in'
                    . ' the aggregate'
                )) . '</span>';
    }
    if ($inlineBody) {
        $out .= '<div class="vp-analyst-text vpa-md vp-analyst-inline">'
            . $markdown($item['body']) . '</div>';
    }
    /*
     * A proposal's target is named by its change strip below, with the
     * attribute id the chip does not carry — so the chip would be the
     * same record said twice at a coarser grain.
     */
    if (!$isProposal) {
        $out .= '<span class="ms-auto">'
            . $attachChip($item['attached_to']) . '</span>';
    }
    $out .= '</div>';

    if ($isProposal) {
        /*
         * **The change, drawn as a change.** A proposal is the one item
         * in this thread that is not somebody's prose about the value —
         * it is an edit somebody wants made to a row — and a sentence
         * saying *proposes 2.2.2.3 in place of 2.2.2.2 on attribute
         * 1495259* buries the only two strings the reader is comparing
         * in the middle of it. Drawn as `old → new` in monospace, with
         * the old struck through, the two are side by side and the
         * difference between `2.2.2.2` and `2.2.2.3` is visible rather
         * than read.
         *
         * Kept out of the body deliberately: the body goes through the
         * markdown renderer, and an indicator containing `*` or `_` is
         * not emphasis.
         */
        $p = $item['proposal'];
        $ops = array(
            'replace' => __('replace'),
            'add' => __('add'),
            'delete' => __('delete'),
            'refile' => __('re-file'),
        );
        $out .= '<div class="vpa-change vpa-change-' . h($p['op'])
            . (empty($p['resolved']) ? '' : ' vpa-change-done') . '">';
        $out .= '<span class="vpa-change-op">' . h($ops[$p['op']])
            . '</span>';

        if ($p['op'] === 'delete') {
            $out .= '<span class="vpa-change-from">' . h(
                $p['target'] === null ? $p['value'] : $p['target']['value']
            ) . '</span>';
        } elseif ($p['op'] === 'add') {
            $out .= '<span class="vpa-change-to">' . h($p['value'])
                . '</span>';
        } elseif ($p['op'] === 'refile') {
            /*
             * No arrow, because nothing moves: the value the proposal
             * carries is the value the target already holds, and what
             * it wants changed is in the type and category beside it.
             */
            $out .= '<span class="vpa-change-keep">' . h($p['value'])
                . '</span>'
                . '<span class="vpa-change-note">'
                . h(__('value unchanged')) . '</span>';
        } else {
            $out .= '<span class="vpa-change-from">'
                . h($p['target']['value']) . '</span>'
                . '<i class="fas fa-arrow-right vpa-change-arrow"'
                . ' aria-hidden="true"></i>'
                . '<span class="vpa-change-to">' . h($p['value'])
                . '</span>';
        }

        $out .= '<span class="vpa-change-meta">' . h(sprintf(
            __('%1$s / %2$s'),
            $p['category'],
            $p['type']
        )) . '</span>';

        // The record the change lands on, at the grain the chip could
        // not carry: which attribute, not only which event.
        $on = $p['target'] === null
            ? array(
                $baseurl . '/events/view/' . (int)$p['event'],
                sprintf(__('a new attribute on #%s'), $p['event']),
            )
            : array(
                $baseurl . '/events/view/' . (int)$p['event']
                    . '#tab-attributes',
                sprintf(
                    __('attribute %1$s in #%2$s'),
                    $p['target']['id'],
                    $p['event']
                ),
            );
        $out .= '<a class="vpa-change-on" href="' . h($on[0]) . '">'
            . h($on[1])
            . '<i class="fas fa-arrow-up-right-from-square"'
            . ' aria-hidden="true"></i></a>';
        $out .= '</div>';
    }

    if ($item['body'] !== '' && !$inlineBody) {
        $out .= '<div class="vp-analyst-text vpa-md">'
            . $markdown($item['body']) . '</div>';
    }

    $out .= '<div class="vp-analyst-meta d-flex align-items-center'
        . ' flex-wrap gap-2"><span>'
        . '<span class="misp-icon misp-icon-organisation misp-simple'
        . ' me-1"></span>'
        /*
         * Linked where the organisation still resolves. Null on the
         * eleven rows whose `orgc_uuid` names an organisation that no
         * longer exists — no name to print and no page to open.
         */
        . (empty($item['org_id'])
            ? h($item['org'])
            : '<a class="vpa-orglink" href="' . h($baseurl)
                . '/organisations/view/' . (int)$item['org_id'] . '">'
                . h($item['org']) . '</a>');
    // A proposal has no author list: `shadow_attributes` records the
    // proposing user's address, not the free-text `authors` a note has.
    if ($item['author'] !== null) {
        $out .= ' &nbsp;&middot;&nbsp; <i class="fas fa-user me-1"></i>'
            . h($item['author']);
    }
    $out .= ' &nbsp;&middot;&nbsp; <i class="fas fa-clock me-1"></i>'
        . ($isProposal
            /*
             * Not when it was written. `shadow_attributes` has no
             * `created`; its one `timestamp` is rewritten on every
             * change **and** stamped at resolution, so a resolved
             * proposal's date is the day it closed.
             */
            ? '<span title="' . h(__(
                'When the proposal last moved. shadow_attributes has no'
                . ' creation date — a resolved proposal carries the day'
                . ' it closed.'
            )) . '">' . h($item['date']) . ' '
                . h(__('(last moved)')) . '</span>'
            : h($item['date']))
        . '</span>';
    // Null on a proposal, which inherits its event's reach rather than
    // declaring one of its own.
    if ($item['distribution'] !== null) {
        $out .= '<span class="badge bg-body-tertiary text-body-secondary'
            . ' border fw-normal" title="'
            . h(sprintf(__('distribution %s'), $item['distribution']))
            . '">'
            . ($distIcon === 'fas fa-lock'
                || $distIcon === 'fas fa-share-nodes'
                    ? '<i class="' . $distIcon . ' me-1"></i>'
                    : '<span class="' . $distIcon . ' me-1"></span>')
            . h($distLabel) . '</span>';
    }
    if (!empty($item['language'])) {
        $out .= '<span class="badge bg-body-tertiary text-body-secondary'
            . ' border fw-normal" title="'
            . h(__(
                'the language column, a natural-language code — not a'
                . ' markup flag'
            )) . '">' . h($item['language']) . '</span>';
    }
    if (!empty($item['children'])) {
        $out .= '<button type="button" class="vpa-replybtn"'
            . ' data-vp-a-replies aria-expanded="true">'
            . '<i class="fas fa-caret-down"></i>'
            . h(__n(
                '%s reply',
                '%s replies',
                count($item['children']),
                count($item['children'])
            )) . '</button>';
    }
    $out .= '</div>';

    $out .= '</div></div>';

    if (!empty($item['children'])) {
        $out .= '<div class="vpa-replies">';
        foreach ($item['children'] as $child) {
            $out .= '<div class="vpa-reply'
                . ($depth >= 1 ? ' vpa-reply-2' : '') . '">'
                . $renderItem($child, $depth + 1) . '</div>';
        }
        $out .= '</div>';
    }

    if (!empty($item['max_depth_reached'])) {
        $out .= '<div class="vpa-depth"><i class="fas fa-ellipsis"></i>'
            . h(__(
                'Two levels is what MISP returns. Anything written below'
                . ' this one is flagged but not fetched.'
            )) . '</div>';
    }

    return $out;
};

/*
 * Nothing written is a state, not four zeroes. A sub-line reading
 * `0 items · 0 opinions, 0 notes · 0 replies · newest first` states
 * the ordering of an empty list, which is the kind of sentence that
 * makes a working page look broken.
 */
$proposals = $counts['proposals'];

$breakdown = sprintf(
    __('%1$s, %2$s'),
    __n('%s opinion', '%s opinions', $counts['opinions'],
        $counts['opinions']),
    __n('%s note', '%s notes', $counts['notes'], $counts['notes'])
);
if ($proposals > 0) {
    $breakdown = sprintf(
        __('%1$s, %2$s'),
        $breakdown,
        __n('%s proposal', '%s proposals', $proposals, $proposals)
    );
}

$subtitle = empty($thread) ? h(__('Nothing written on this value')) : implode(' &nbsp;·&nbsp; ', array(
    h(sprintf(
        __('%s on this value'),
        __n('%s item', '%s items', $counts['items'], $counts['items'])
    )),
    h($breakdown),
    h(sprintf(
        __('%s written on them'),
        __n(
            '%s reply',
            '%s replies',
            $counts['replies'],
            $counts['replies']
        )
    )),
    h(__('newest first')),
));

$sorts = array(
    'newest' => __('Newest'),
    'oldest' => __('Oldest'),
    'org' => __('By organisation'),
);
$pills = array(
    'all' => sprintf(__('All %s'), $counts['items']),
    'note' => sprintf(__('Notes %s'), $counts['notes']),
    'opinion' => sprintf(__('Opinions %s'), $counts['opinions']),
);
/*
 * Only when there are any. A permanent `Proposals 0` pill on the many
 * values that have none is a control that does nothing, on a tab where
 * every other pill filters to something.
 */
if ($proposals > 0) {
    $pills['proposal'] = sprintf(__('Proposals %s'), $proposals);
}

$headerExtra = '';
if (!empty($thread)) {
    $headerExtra .= '<div class="btn-group btn-group-sm" role="group"'
        . ' aria-label="' . h(__('Order')) . '">';
    foreach ($sorts as $key => $label) {
        $headerExtra .= '<button type="button" class="btn'
            . ' btn-outline-secondary text-nowrap'
            . ($key === 'newest' ? ' active' : '') . '"'
            . ' data-vp-a-sort="' . h($key) . '"'
            . ' aria-pressed="' . ($key === 'newest' ? 'true' : 'false')
            . '">' . h($label) . '</button>';
    }
    $headerExtra .= '</div>';

    $headerExtra .= '<div class="btn-group btn-group-sm" role="group"'
        . ' aria-label="' . h(__('Kind')) . '">';
    foreach ($pills as $key => $label) {
        $headerExtra .= '<button type="button" class="btn'
            . ' btn-outline-secondary text-nowrap'
            . ($key === 'all' ? ' active' : '') . '"'
            . ' data-vp-a-kind-filter="' . h($key) . '"'
            . ' aria-pressed="' . ($key === 'all' ? 'true' : 'false')
            . '">' . h($label) . '</button>';
    }
    $headerExtra .= '</div>';
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-dense"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-thread>

    <?= $this->element('Values/View/value_panel_header', array(
        /*
         * Unconditional, and it names what the panel can hold rather
         * than what this value happens to have — the same convention as
         * *Tags and galaxies* on the Overview, which is titled that way
         * on a value with no galaxy. A title that changed with the data
         * also meant the loading skeleton could not match it, so a
         * value with proposals renamed its own panel mid-load.
         */
        'panelTitle' => __('Notes, opinions and proposals'),
        'panelIcon' => 'misp-icon misp-icon-analyst-note misp-simple',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra === '' ? null : $headerExtra,
    )) ?>

    <?php if (empty($thread)): ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-analyst-note misp-simple"></span>
            <span><?=
                __('Nobody has written a note or an opinion on this value.')
            ?></span>
        </div>
    <?php else: ?>
        <div class="p-3">
            <div class="vpa-thread">
                <?php foreach ($thread as $i => $item): ?>
                    <div class="vpa-item"
                         data-vp-a-item
                         data-vp-a-kind="<?= h($item['kind']) ?>"
                         data-vp-a-org="<?= h($item['org']) ?>"
                         data-vp-a-date="<?= h($item['date']) ?>"
                         data-vp-a-order="<?= $i ?>">
                        <?= $renderItem($item, 0) ?>
                    </div>
                <?php endforeach; ?>
            </div>
            <div class="vp-empty-inline d-none" data-vp-a-empty>
                <i class="fas fa-filter"></i>
                <span><?= __('No item of that kind on this value.') ?></span>
            </div>
        </div>
    <?php endif; ?>

    <?php
    /*
     * A note or an opinion is written on the value itself, by the SHA-256
     * of its text, through MISP's own analyst-data form. The form returns
     * to this page, where the thread reads it back.
     */
    $canWrite = !empty($me['Role']['perm_analyst_data'])
        && $this->Acl->canAccess('analystData', 'add');
    $hex = hash('sha256', (string)$valueIntelligence['value']);
    ?>
    <div class="p-3 border-top d-flex align-items-center flex-wrap gap-2">
        <span class="fw-semibold me-auto"><?= h(__('Write about this value')) ?></span>
        <?php foreach (array(
            'Note' => array('misp-icon misp-icon-analyst-note misp-simple', __('Add note')),
            'Opinion' => array('misp-icon misp-icon-analyst-opinion misp-simple', __('Add opinion')),
        ) as $kind => list($icon, $label)): ?>
            <?php if ($canWrite): ?>
                <button type="button" class="btn btn-outline-primary btn-sm fw-semibold"
                        onclick="openModal(<?= h(json_encode(
                            $baseurl . '/analystData/add/' . $kind . '/' . $hex . '/AttributeValue',
                            JSON_UNESCAPED_SLASHES
                        )) ?>)">
                    <span class="<?= h($icon) ?> me-1"></span><?= h($label) ?>
                </button>
            <?php else: ?>
                <span class="d-inline-block" tabindex="0"
                      title="<?= h(__('Your role does not allow writing analyst data.')) ?>">
                    <button type="button" class="btn btn-outline-primary btn-sm fw-semibold" disabled>
                        <span class="<?= h($icon) ?> me-1"></span><?= h($label) ?>
                    </button>
                </span>
            <?php endif; ?>
        <?php endforeach; ?>
    </div>

    <?php if (!empty($analyst['capped'])): ?>
        <?php
        /*
         * The union is assembled from the newest cap-many occurrences,
         * so past the cap a note written on one this read did not reach
         * is a note the panel cannot show. Said rather than absorbed:
         * this is the one condition under which the thread is a slice
         * and looks exactly like a whole.
         */
        ?>
        <p class="vp-aside-note"><?= h(sprintf(
            __('This value has more occurrences than one read takes, so'
                . ' the thread was assembled from the %s most recent of'
                . ' them and their events. A note written on an older'
                . ' occurrence is not shown.'),
            $stats['shown']
        )) ?></p>
    <?php endif; ?>

    <?php
    /*
     * **No withheld-items band, and it was removed rather than
     * reworded.** `05-analyst.md` §11 recorded that the count is not
     * obtainable — `buildConditions` scopes the fetch and there is no
     * unscoped count to subtract — and concluded the tab should
     * therefore say that items exist without saying how many. §14.6
     * does not survive that: a panel must not be usable as an
     * existence oracle, and *analyst data exists here that you cannot
     * see* is one with the number filed off, which is worse than a
     * count rather than milder — the same disclosure with no way to
     * gauge it. Removed as it was from Occurrences and from the
     * Timeline. `26-analyst.md` D7.
     *
     * The standing panel beside this one carries §14.6's permanent
     * caveat instead, because it computes a judgement; this one renders
     * rows and gets nothing.
     */
    ?>
</div>
