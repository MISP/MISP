<?php
/*
 * Brings the row a focus:<uuid> deep link names into view in an event's
 * attribute or object tab, opening its object card first.
 *
 * - $focusId (int|null) id of the attribute row, null when it is not on this page
 */
if (empty($focusId)) {
    return;
}
$markerId = 'list-focus-' . dechex(mt_rand());
?>
<span class="d-none" id="<?= $markerId ?>"></span>
<script>
(function () {
    var marker = document.getElementById(<?= json_encode($markerId) ?>);
    if (!marker) return;
    var container = marker.closest('.ajax-tab-content') || marker.parentNode;
    marker.remove();
    // Applied once: a reload of the tab (filter, sort, page) starts from the list itself
    if (container.dataset.url) {
        container.dataset.url = container.dataset.url.replace(/\/focus:[^/]*/, '');
    }
    var row = container.querySelector('tr[data-primary-id="<?= (int)$focusId ?>"]');
    if (!row) return;
    row.classList.add('ov-focus-row');
    var reveal = function () { row.scrollIntoView({ block: 'center' }); };
    var collapse = row.closest('.accordion-collapse');
    if (collapse && !collapse.classList.contains('show') && window.bootstrap) {
        collapse.addEventListener('shown.bs.collapse', reveal, { once: true });
        bootstrap.Collapse.getOrCreateInstance(collapse, { toggle: false }).show();
    } else {
        reveal();
    }
}());
</script>
