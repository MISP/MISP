<?php
// Extraction des données (liste de strings)
$data = Hash::extract($row, $field['data_path']);

if (empty($data)) {
    return;
}

// Si les données sont imbriquées (ex: [['JSON', 'STIX']]), on aplatit
if (is_array($data) && isset($data[0]) && is_array($data[0])) {
    $data = $data[0];
}

$maxVisible = 3; // On en montre moins car ils sont plus larges
$total = count($data);
$hiddenCount = max(0, $total - $maxVisible);
$containerId = 'format-container-' . uniqid();
?>

<div id="<?= $containerId ?>" class="format-container d-inline-flex flex-wrap align-items-center">

    <?php foreach ($data as $index => $formatName): 
        $isHidden = ($index >= $maxVisible);
        $hiddenClass = $isHidden ? 'd-none extra-format' : '';

        echo $this->element('genericElementsBS5/Badges/format', [
            'formatName' => $formatName,
            'hiddenClass' => $hiddenClass
        ]);
    endforeach; ?>

    <?php if ($hiddenCount > 0): ?>
        <button
            class="badge bg-dark text-white border border-primary ms-1 mb-1 format-expand-btn"
            style="cursor:pointer; transition: all 0.2s;"
            onclick="toggleFormats(this, '<?= $containerId ?>')"
        >
            <i class="fas fa-plus small me-1"></i><?= $hiddenCount ?>
        </button>
    <?php endif; ?>

</div>