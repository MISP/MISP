<?php
    $randomId = RandomTool::random_str(true, 8);;
    if (isset($field['raw'])) {
        $string = $field['raw'];
    } else {
        $value = Hash::get($data, $field['path']);
        $string = is_null($value) ? '' : $value;
    }
    echo sprintf(
        '<div>%s</div><div class="collapse json_container_%s"></div>',
        empty($field['collapsible']) ? '' : sprintf(
            '<button class="btn btn-primary btn-xs" data-bs-toggle="collapse" data-bs-target=".json_container_%s" aria-expanded="false" aria-controls="Show JSON"><i class="fas fa-eye"></i></a>',
            h($randomId)
        ),
        h($randomId)
    );
?>

<script type="text/javascript">
$(document).ready(function() {
    $('.json_container_<?php echo h($randomId);?>').html(syntaxHighlightJson(<?php echo json_encode($string); ?>, 4));
});
</script>
