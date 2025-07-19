<?php
    $data = Hash::extract($row, $field['data_path']);
    // I feed dirty for this...
    if (is_array($data) && count($data) === 1 && isset($data[0])) {
        $data = $data[0];
    }
    echo sprintf(
        '<div class="json_container_%s"></div>',
        h($k)
    );

    // hacky way of keeping single element arrays as well as potentially json encoded strings in an array (what the fuck made me add this case 6 years ago anyway?)
    if (is_string($data)) {
        $temp = json_decode($data, true);
        if ($temp !== null) {
            $data = $temp;
        } else {
            $data = [$data];
        }
    }
?>
<script type="text/javascript">
$(document).ready(function() {
    $('.json_container_<?php echo h($k);?>').html(syntaxHighlightJson(<?php echo json_encode($data); ?>, 4));
});
</script>
