<?php
$data = Hash::extract($row, $field['data_path']);

if (empty($data)) {
    return;
}

$maxVisible = 4;
$totalGalaxies = count($data);
$hiddenCount = max(0, $totalGalaxies - $maxVisible);

?>

<div class="galaxy-container d-inline-flex flex-wrap align-items-center">

<?php
foreach ($data as $index => $item) {
    if (!empty($item['Galaxy'])) {
        $galaxy = $item['Galaxy'];
        $cluster = $item;
    }
    else if (!empty($item['GalaxyCluster'])) {
        $galaxy = $item;
        $cluster = $item['GalaxyCluster'][0];
    }
    else {
        continue;
    }

    $name = h($galaxy['name']) . ' : ' . h($cluster['value']);
    $local = h($cluster['local']);
    $bgColor = 'background-color: #e7f1ff';
    $textColor = '#084298';
    $shadow = 'filter: drop-shadow(-1px 3px 2px rgba(50, 50, 0, 0.5))';
    $metallicEffect = "background-image: linear-gradient(145deg, rgba(255,255,255,0.25) 0%, rgba(255,255,255,0.05) 40%, rgba(0,0,0,0.05) 100%)";
    $text = "text-align:left; white-space:normal; word-wrap:break-word";

    $style = sprintf('%s; color: %s; %s; %s; %s;  cursor:pointer;', $bgColor, $textColor, $shadow, $metallicEffect, $text);
    if ($local) {
        $style .= sprintf(' border:2px dashed %s', $textColor);
    }

    $hiddenClass = ($index >= $maxVisible) ? 'd-none extra-galaxies' : '';
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
        class="badge bg-secondary text-white me-1 mb-1 galaxy-expand"
        style="cursor:pointer;"
        onclick="toggleGalaxies(this)"
    >
        +<?= $hiddenCount ?>
    </span>
<?php endif; ?>

</div>

<script>
function toggleGalaxies(badge) {
    const container = badge.closest('.galaxy-container');
    const hiddenGalaxies = container.querySelectorAll('.extra-galaxies');

    if (!hiddenGalaxies.length) return;

    const isHidden = hiddenGalaxies[0].classList.contains('d-none');

    hiddenGalaxies.forEach(g => g.classList.toggle('d-none'));

    badge.textContent = isHidden ? '−' : '+' + hiddenGalaxies.length;
}
</script>