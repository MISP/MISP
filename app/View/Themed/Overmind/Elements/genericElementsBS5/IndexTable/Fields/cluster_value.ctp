<?php
/*
 * cluster_value.ctp
 *
 * Renders a galaxy cluster summary: distribution + published badges, the value,
 * a truncated description and a "forked from" indicator.
 *
 * Expected:
 * $field['data_path']       => path to the cluster array (e.g. 'GalaxyCluster',
 *                              'SourceCluster', 'TargetCluster').
 * $field['url']             => optional link template for the value (supports %id%).
 * $field['hide_description'] => optional bool, hide the description line.
 */
$basePath = $field['data_path'];
$cluster = Hash::extract($row, $basePath);

if (empty($cluster)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

// Optional link on the value.
$valueHtml = h($cluster['value'] ?? '');
if (!empty($field['url']) && !empty($cluster['id'])) {
    $valueHtml = '<a href="' . h(str_replace('%id%', h($cluster['id']), $field['url']))
        . '" class="text-decoration-none">' . $valueHtml . '</a>';
}

// A "forked from" parent is only available when the controller attaches it.
$parent = $cluster['extended_from']['GalaxyCluster'] ?? null;
?>

<div class="d-flex flex-column">
    <div class="d-flex align-items-center gap-2 flex-wrap mb-0">
        <?php if (!$isCard):
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/distribution',
                [
                    'row' => $row,
                    'field' => [
                        'data_path' => $basePath . '.distribution',
                        'display' => 'short'
                    ]
                ]
            );
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/published',
                [
                    'row' => $row,
                    'field' => ['data_path' => $basePath . '.published']
                ]
            );
        endif; ?>

        <p class="mb-0 fw-semibold" style ="font-size: 1.2em;">
            <?= $valueHtml ?>
        </p>
    </div>
    <!-- Description: compact, single-line, truncated (full text on hover) -->
    <?php if (empty($field['hide_description']) && !empty($cluster['description'])):
        $desc = trim($cluster['description']);
    ?>
        <div class="text-muted fst-italic text-truncate mt-1"
             style="font-size:.8em; max-width:520px;"
             title="<?= h($desc) ?>">
            <i class="fa fa-comment opacity-50 me-1"></i><?= h($desc) ?>
        </div>
    <?php endif; ?>

    <!-- Fork indicator: shown when the parent cluster info is attached -->
    <?php if (!empty($parent['id'])): ?>
        <div class="mt-1">
            <span class="badge d-inline-flex align-items-center gap-1 fw-semibold"
                  style="background:transparent;color:var(--bs-galaxy);border:1px dashed var(--bs-galaxy);"
                  title="<?= __('This cluster is forked from another cluster') ?>">
                <i class="fas fa-code-branch"></i>
                <?= __('Forked from') ?>
                <a href="<?= $baseurl ?>/galaxy_clusters/view/<?= h($parent['id']) ?>"
                   class="text-galaxy text-decoration-none"><?= h($parent['value'] ?? '') ?></a>
            </span>
        </div>
    <?php endif; ?>
</div>
