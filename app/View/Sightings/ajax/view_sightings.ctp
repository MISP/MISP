<?= $this->element('genericElements/assetLoader', [
    'css' => ['sightingstyle'],
    'js' => ['d3', 'd3.custom'],
]);
?>
<div id="graphContent"></div>
<script>
    sightingsGraph("#graphContent", "<?= $csv ?>");
</script>
