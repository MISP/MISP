<?php
$randomId = dechex(mt_rand());
$containerId = empty($scaffold_data['containerId'])
    ? 'index' . $randomId
    : $scaffold_data['containerId'];

echo '<div id="' . $containerId . '_content">';
?>

<div class="container-fluid">

    <!-- CARD 1 : FILTERS -->
    <?php if (!empty($scaffold_data['data']['filter_bar'])): ?>
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <?= $this->element(
                'genericElementsBS5/IndexTable/filter_bar',
                [
                    'scaffold_data' => $scaffold_data['data'],
                    'item_url' => $item_url
                ]); ?>
            </div>
        </div>
    <?php endif; ?>

    <!-- CARD 2 : DATA -->
    <div class="card shadow-sm mb-4">
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
    <?php if (empty($scaffold_data['data']['skip_pagination'])): ?>
        <div class="card shadow-sm mb-5">
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


<?php
echo '</div>';
?>