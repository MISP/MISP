<?php
/**
 * The mark on a value MISP already knows to be benign.
 *
 * The banner's chip at row scale — same class, same `--warninglist`
 * colour, a modifier for the padding — so the frame and the tables read
 * as one statement once the Overview goes live. Icon-only, because the
 * words *"Warninglist hit"* cost a column's worth of width on every
 * listed row and the tooltip is one hover away.
 *
 * The tooltip names the list **and the entry that matched**, which are
 * not the same thing: `10.0.5.23` is listed because `10.0.0.0/8` is,
 * and a tooltip saying only *"List of RFC 5735 CIDR blocks"* leaves a
 * reader to work out which of its entries caught this row. Where the
 * curator wrote a note against the entry it follows on its own line —
 * `Warninglist::assignComments` fetches those whether or not anyone
 * reads them, and that fetch is the one query the whole lookup costs.
 *
 * An element and not a closure because three tables across two
 * templates draw it — the co-occurrence values, their object siblings,
 * and the dated relations — and one mark drawn three ways would be
 * three things to keep in step. Written as pure PHP with no literal
 * text outside the tags and no closing `?>`, so it contributes no stray
 * whitespace to the rows it sits in.
 *
 * Callers guard the call rather than relying on the early return, so an
 * unlisted row costs no element render at all:
 *
 *     <?= empty($row['warninglists']) ? '' : $this->element(
 *         'Values/View/value_warninglist_mark',
 *         array('lists' => $row['warninglists'])) ?>
 *
 * @var array $lists id, name, category, matched, comment
 */
$lists = isset($lists) ? $lists : array();
if (empty($lists)) {
    return;
}
$title = array();
foreach ($lists as $list) {
    $line = sprintf(
        __('%1$s (%2$s) — matched %3$s'),
        $list['name'],
        $list['category'],
        $list['matched']
    );
    if (!empty($list['comment'])) {
        $line .= "\n" . $list['comment'];
    }
    $title[] = $line;
}
echo '<span class="vp-warninglist-chip vp-warninglist-mark" title="'
    . h(implode("\n", $title)) . '">'
    . '<i class="fas fa-list-check"></i>'
    . '<span class="visually-hidden">'
    . h(__('On a warninglist')) . '</span></span>';
