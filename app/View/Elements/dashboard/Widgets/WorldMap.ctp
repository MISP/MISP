<?php
    $css_collection = array(
        'jquery-jvectormap-2.0.5'
    );
    $js_collection = array(
        'jquery-jvectormap-2.0.5.min',
        'jquery-jvectormap-world-mill'
    );
    echo $this->element('genericElements/assetLoader', array(
        'css' => $css_collection,
        'js' => $js_collection,
        'meta' => 'icon'
    ));
    $randomNumber = rand();
?>

<div id="world-map-<?= $randomNumber ?>" style="width: 600px; height: 400px"></div>
<script>
    var mapData = <?= json_encode($data['data']); ?>;
    $('#world-map-<?= $randomNumber ?>').vectorMap({
        map: 'world_mill',
        series: {
            regions: [{
                values: mapData,
                scale: ['#F08080', '#8B0000'],
                normalizeFunction: 'polynomial'
            }]
        },
        onRegionTipShow: function(e, el, code) {
            el.html(el.html()+' (<?= h($data['scope']) ?> - '+mapData[code]+')');
        }
    });
    var container_<?= $randomNumber ?> = $('#world-map-<?= $randomNumber ?>').parent().parent();

    function resizeDashboardWorldMap(id) {
        var width = eval('container_' + id + '.width()');
        var height = eval('container_' + id + '.height() - 60');
        $('#world-map-' + id).css('width', width + 'px');
        $('#world-map-' + id).css('height', height + 'px');
        $('#world-map-' + id).vectorMap('get','mapObject').updateSize();
    }
    $(document).ready(function() {
        resizeDashboardWorldMap(<?= $randomNumber ?>);
    });
</script>
