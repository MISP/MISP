<?php
$randomId = dechex(mt_rand());
$containerId = empty($scaffold_data['containerId'])
    ? 'index' . $randomId
    : $scaffold_data['containerId'];

echo '<div id="' . $containerId . '_content" data-ifp-scope="' . h($item_url) . '">';
?>

<div class="container-fluid">

    <?= $scaffold_data['data']['before_filter_bar'] ?? '' ?>

    <?php
    // Mirrors filter_bar.ctp: every bar is a picker bar unless it opts out.
    $barData = $scaffold_data['data']['filter_bar'] ?? [];
    $pickerBar = !empty($barData) && (
        ($barData['picker_bar'] ?? true)
        || !empty(array_filter($barData['children'] ?? [], function ($child) {
            return ($child['type'] ?? '') === 'picker';
        }))
    );
    ?>

    <!-- CARD 1 : FILTERS -->
    <?php if (!empty($scaffold_data['data']['filter_bar'])): ?>
        <div class="<?= $pickerBar ? 'ifp-card' : 'card shadow-sm mb-4' ?>">
            <div class="<?= $pickerBar ? '' : 'card-body' ?>">
                <?= $this->element(
                'genericElementsBS5/IndexTable/filter_bar',
                [
                    'scaffold_data' => $scaffold_data['data'],
                    'item_url' => $item_url
                ]); ?>
            </div>
        </div>
    <?php endif; ?>

    <!-- CARD 2 + 3 : DATA AND PAGINATION -->
    <div id="index-results" class="index-results" data-ifp-results>

    <?= $scaffold_data['data']['before_results'] ?? '' ?>

    <div class="card shadow-sm mb-4" data-tour="index-table">
        <div class="card-body p-0">
            <div id="tableView">
                <?= $this->element(
                'genericElementsBS5/IndexTable/index_table', 
                [
                    'scaffold_data' => $scaffold_data
                ]); ?>
            </div>

            <div id="cardView" class="d-none">
                <?= $this->element(
                'genericElementsBS5/IndexTable/index_card', 
                [
                    'scaffold_data' => $scaffold_data
                ]); ?>
            </div>
        </div>
    </div>

    <!-- CARD 3 : PAGINATION -->
    <?php if (empty($scaffold_data['data']['skip_pagination']) && $pickerBar): ?>
        <?= $this->element('genericElementsBS5/IndexTable/pagination_bottom', [
            'rows' => count($scaffold_data['data']['data'] ?? []),
        ]) ?>
    <?php elseif (empty($scaffold_data['data']['skip_pagination'])): ?>
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <?= $this->element(
                    'genericElementsBS5/IndexTable/pagination',
                    [
                        'scaffold_data' => $scaffold_data
                    ]); ?>
            </div>
        </div>
    <?php endif; ?>

    </div>

</div>


<?php
echo '</div>';
?>