<?= $this->element('genericElements/assetLoader', [
    'css' => ['sightingstyle'],
    'js' => ['d3', 'd3.custom'],
]);
?>
<div id="graphContent" class="graphContent"></div>
<script>
    sightingsGraph("#graphContent", "<?= $csv; ?>");
</script>
