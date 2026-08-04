<?php
echo $this->element(
    'Objects/object_add_attributes',
    [
        'element'     => $element,
        'k'           => $k,
        'appendValue' => '0',
    ]
);
?>
<script>
(function () {
    if (typeof window.overmindEnableObjectRow === 'function') {
        window.overmindEnableObjectRow(<?= (int)$k ?>);
    }
}());
</script>