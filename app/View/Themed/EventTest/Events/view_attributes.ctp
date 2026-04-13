<?php
/**
 * AJAX-loaded attribute listing for view2.
 * Wraps the existing row_attribute.ctp element for
 * full feature parity with the original event view.
 *
 * Variables: $attributes, $total, $page, $limit,
 *   $event, $mayModify, $mayChangeCorrelation,
 *   $extended, $extending, $includeOrgColumn,
 *   $includeSightingdb, $includeDecayScore,
 *   $includeRelatedTags, $attrDescriptions,
 *   $shortDist, $flatten, $searchFor
 */
$eventId = $event['Event']['id'];
$totalPages = $limit > 0
    ? (int)ceil($total / $limit) : 1;

$fieldCount = 10;
if (
    $extended ||
    ($mayModify && !empty($attributes))
) {
    $fieldCount++;
}
if (!empty($includeOrgColumn)) {
    $fieldCount++;
}
if (!empty($includeRelatedTags)) {
    $fieldCount++;
}
if (!empty($includeSightingdb)) {
    $fieldCount++;
}
if (!empty($includeDecayScore)) {
    $fieldCount++;
}
?>
<div id="attributeListContainer">
    <div class="attribute-controls"
         style="margin-bottom:10px;
                display:flex;
                align-items:center;
                gap:15px;">
        <label style="margin:0;cursor:pointer;"
               title="<?= __(
                   'Include attributes that belong'
                   . ' to objects'
               ) ?>">
            <input type="checkbox"
                   id="attr-flatten-toggle"
                   <?= !empty($flatten)
                       ? 'checked' : '' ?>
                   style="margin-right:4px;">
            <?= __('Include object attributes') ?>
        </label>
        <div style="flex:1;max-width:300px;">
            <input type="text"
                   id="attr-quick-filter"
                   class="form-control input-sm"
                   placeholder="<?= __(
                       'Filter by value...'
                   ) ?>"
                   value="<?= h($searchFor) ?>"
                   style="width:100%;">
        </div>
    </div>

    <div class="pagination-info"
         style="margin-bottom:8px;">
        <strong><?= __n(
            '%s attribute', '%s attributes',
            $total, $total
        ) ?></strong>
        <?php if ($totalPages > 1): ?>
            &mdash; <?= __(
                'Page %s of %s',
                $page, $totalPages
            ) ?>
        <?php endif; ?>
    </div>

<?php if (!empty($attributes)): ?>
    <table class="table table-striped
                   table-condensed">
        <tr>
            <?php
                if (
                    $extended ||
                    ($mayModify && !empty($attributes))
                ):
            ?>
                <th>
                    <input class="select_all"
                           type="checkbox"
                           title="<?= __('Select all') ?>"
                           role="button" tabindex="0"
                           aria-label="<?= __(
                               'Select all attributes'
                               . '/proposals on'
                               . ' current page'
                           ) ?>"
                           onclick="toggleAllAttributeCheckboxes()">
                </th>
            <?php endif; ?>
            <th class="context hidden">
                <?= __('ID') ?>
            </th>
            <th class="context hidden">
                <?= __('UUID') ?>
            </th>
            <th class="context hidden">
                <?= __('First seen') ?>
                <i class="fas fa-arrow-right"></i>
                <?= __('Last seen') ?>
            </th>
            <th><?= __('Date') ?></th>
            <th class="context">
                <?= __('Context') ?>
            </th>
            <?php if ($extended || $extending): ?>
                <th class="event_id">
                    <?= __('Event') ?>
                </th>
            <?php endif; ?>
            <?php if ($includeOrgColumn): ?>
                <th><?= __('Org') ?></th>
            <?php endif; ?>
            <th><?= __('Category') ?></th>
            <th><?= __('Type') ?></th>
            <th><?= __('Value') ?></th>
            <th><?= __('Tags') ?></th>
            <?php if ($includeRelatedTags): ?>
                <th><?= __('Related Tags') ?></th>
            <?php endif; ?>
            <th><?= __('Galaxies') ?></th>
            <th><?= __('Comment') ?></th>
            <th><?= __('Correlate') ?></th>
            <th><?= __('Related Events') ?></th>
            <?php if (
                $me['Role']['perm_view_feed_correlations']
            ): ?>
                <th><?= __('Feed hits') ?></th>
            <?php endif; ?>
            <th title="<?= h(
                $attrDescriptions['signature']['desc']
            ) ?>">
                <?= __('IDS') ?>
            </th>
            <th title="<?= h(
                $attrDescriptions['distribution']['desc']
            ) ?>">
                <?= __('Distribution') ?>
            </th>
            <th><?= __('Sightings') ?></th>
            <th><?= __('Activity') ?></th>
            <?php if (!empty($includeSightingdb)): ?>
                <th><?= __('SightingDB') ?></th>
            <?php endif; ?>
            <?php if (!empty($includeDecayScore)): ?>
                <th class="decayingScoreField"
                    title="<?= __('Decaying Score') ?>">
                    <?= __('Score') ?>
                </th>
            <?php endif; ?>
            <th class="actions">
                <?= __('Actions') ?>
            </th>
        </tr>
        <?php
            foreach ($attributes as $k => $attribute) {
                echo $this->element(
                    '/Events/View/row_attribute',
                    [
                        'object' => $attribute,
                        'k' => $k,
                        'mayModify' => $mayModify,
                        'mayChangeCorrelation' =>
                            $mayChangeCorrelation,
                        'fieldCount' => $fieldCount,
                    ]
                );
                if (
                    !empty($attribute['ShadowAttribute'])
                ):
        ?>
                    <tr class="blank_table_row">
                        <td colspan="<?= $fieldCount ?>">
                        </td>
                    </tr>
        <?php
                endif;
            }
        ?>
    </table>
<?php else: ?>
    <p><em><?= __(
        'No attributes found.'
    ) ?></em></p>
<?php endif; ?>

<?php if ($totalPages > 1): ?>
    <div class="pagination"
         style="text-align:center;">
        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
            <?php if ($p === (int)$page): ?>
                <span class="badge badge-inverse">
                    <?= $p ?>
                </span>
            <?php else: ?>
                <a href="#"
                   onclick="loadAttributePage(<?=
                       $p
                   ?>); return false;"
                   class="badge">
                    <?= $p ?>
                </a>
            <?php endif; ?>
        <?php endfor; ?>
    </div>
<?php endif; ?>
</div>

<script>
(function() {
    var eventId = '<?= h($eventId) ?>';
    var currentFlatten = <?= !empty($flatten)
        ? 'true' : 'false' ?>;
    var currentSearch = '<?= h($searchFor) ?>';
    var searchTimer = null;

    function reloadAttributes(params) {
        params = params || {};
        var flatten = params.flatten !== undefined
            ? params.flatten : currentFlatten;
        var search = params.search !== undefined
            ? params.search : currentSearch;
        var page = params.page || 1;

        var url = baseurl
            + '/events/viewAttributes/' + eventId
            + '/page:' + page;
        if (flatten) {
            url += '/flatten:1';
        }
        if (search) {
            url += '/searchFor:' + encodeURIComponent(
                search
            );
        }

        $.ajax({
            type: 'get',
            url: url,
            beforeSend: function() {
                $('#attributeListContainer')
                    .css('opacity', '0.5');
            },
            success: function(data) {
                $('#attributes_panel-collapse-inner')
                    .html(data);
            },
            error: function() {
                $('#attributeListContainer')
                    .css('opacity', '1');
                showMessage(
                    'fail',
                    'Could not load attributes.'
                );
            }
        });
    }

    $('#attr-flatten-toggle').on(
        'change', function() {
            currentFlatten = $(this).is(':checked');
            reloadAttributes({
                flatten: currentFlatten,
                page: 1
            });
        }
    );

    $('#attr-quick-filter').on(
        'keyup', function() {
            var val = $(this).val().trim();
            clearTimeout(searchTimer);
            searchTimer = setTimeout(function() {
                currentSearch = val;
                reloadAttributes({
                    search: val,
                    page: 1
                });
            }, 400);
        }
    );

    window.loadAttributePage = function(page) {
        reloadAttributes({page: page});
    };
})();
</script>
