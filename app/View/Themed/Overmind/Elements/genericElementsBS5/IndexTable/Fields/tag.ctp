<?php
$data = Hash::extract($row, $field['data_path']);

if (empty($data)) {
    return;
}

$maxVisible = 4;
$totalTags = count($data);
$hiddenCount = max(0, $totalTags - $maxVisible);

?>

<div class="tag-container d-inline-flex flex-wrap align-items-center">

<?php
$visibleIndex = 0;

foreach ($data as $tagWrapper) {
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
    $text = "text-align:left; white-space:normal; word-wrap:break-word";

    $style = sprintf('%s; color: %s; %s; %s; %s; cursor:pointer;', $bgColor, $textColor, $shadow, $metallicEffect, $text);
    if ($local) {
        $style .= sprintf(' border:2px dashed %s', $textColor);
    }

    $hiddenClass = ($visibleIndex >= $maxVisible) ? 'd-none extra-tag' : '';
    ?>

    <span class="badge me-1 mb-1 <?= $hiddenClass ?>" style="<?= $style ?>">
        <?php if ($local): ?>
            <i class="fas fa-user me-1"></i>
        <?php endif; ?>
        <?= $name ?>
    </span>
<?php
    $visibleIndex++;
}
?>

<?php if ($hiddenCount > 0): ?>
    <span
        class="badge bg-secondary text-white me-1 mb-1 tag-expand"
        style="cursor:pointer;"
        onclick="toggleTags(this)"
    >
        +<?= $hiddenCount ?>
    </span>
<?php endif; ?>

</div>


<script>
function toggleTags(badge) {
    const container = badge.closest('.tag-container');
    const hiddenTags = container.querySelectorAll('.extra-tag');

    if (!hiddenTags.length) return;

    const isHidden = hiddenTags[0].classList.contains('d-none');

    hiddenTags.forEach(g => g.classList.toggle('d-none'));

    badge.textContent = isHidden ? '−' : '+' + hiddenTags.length;
}
</script>
