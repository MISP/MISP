<?php
$data = Hash::extract($row, $field['data_path']);

if (empty($data)) {
    return;
}

$maxVisible = 4;
$totalTags = count($data);
$hiddenCount = max(0, $totalTags - $maxVisible);

$rowId = 'tag-row-' . $k; // unicity for each line

?>

<div class="tag-container d-inline-flex flex-wrap align-items-center" id="<?= $rowId ?>">

<?php
foreach ($data as $index => $tagWrapper) {
    if (empty($tagWrapper['Tag'])) {
        continue;
    }

    $tag = $tagWrapper['Tag'];

    $name = h($tag['name']);
    $local = h($tagWrapper['local']);
    $bgColor = 'background-color:' . h($tag['colour']);
    $textColor = $this->TextColour->getTextColour($tag['colour']);
    $shadow = 'filter: drop-shadow(-1px 3px 2px rgba(50, 50, 0, 0.5))';
    $metallicEffect = "background-image: linear-gradient(145deg, rgba(255,255,255,0.25) 0%, rgba(255,255,255,0.05) 40%, rgba(0,0,0,0.05) 100%)";

    $style = sprintf('%s; color: %s; %s; %s;', $bgColor, $textColor, $shadow, $metallicEffect);
    if ($local) {
        $style .= sprintf(' border:2px dashed %s', $textColor);
    }

    $hiddenClass = ($index >= $maxVisible) ? 'd-none extra-tag' : '';
    ?>
    
    <span class="badge me-1 mb-1 <?= $hiddenClass ?>" style="<?= $style ?>">
        <?php if ($local): ?>
            <i class="fas fa-user me-1"></i>
        <?php endif; ?>
        <?= $name ?>
    </span>
<?php
}
?>

<?php if ($hiddenCount > 0): ?>
    <span
        class="badge bg-secondary text-white me-1 mb-1 tag-expand"
        style="cursor:pointer;"
        onclick="toggleTags('<?= $rowId ?>', this)"
    >
        +<?= $hiddenCount ?>
    </span>
<?php endif; ?>

</div>

<script>
function toggleTags(containerId, badge) {
    const container = document.getElementById(containerId);
    const hiddenTags = container.querySelectorAll('.extra-tag');

    const isHidden = hiddenTags[0]?.classList.contains('d-none');

    hiddenTags.forEach(tag => {
        tag.classList.toggle('d-none');
    });

    if (isHidden) {
        badge.textContent = '−';
    } else {
        const hiddenCount = hiddenTags.length;
        badge.textContent = '+' + hiddenCount;
    }
}
</script>