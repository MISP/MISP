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
    if (empty($data['colour_scale'])) {
        $data['colour_scale'] = json_encode(array(
            '#003FBF','#0063BF','#0087BF','#00ACBF','#00BFAD','#00BF89','#00BF64',
            '#00BF40','#00BF1C','#08BF00','#2CBF00','#51BF00','#75BF00','#99BF00',
            '#BEBF00','#BF9B00','#BF7700','#BF5200','#BF2E00','#BF0900'
        ), true);
    }
?>

<div id="world-map-<?= $randomNumber ?>" style="width: 600px; height: 400px"></div>
<script>
    (function() { // variables and functions have their own scope (no override)
        'use strict';
        var randomNumber = "<?= $randomNumber ?>";
        var scope = "<?= h($data['scope']) ?>";
        var resize_timeout;
        var mapData = <?= json_encode($data['data']); ?>;
        var $worldmap = $('#world-map-'+randomNumber);
        var $container = $worldmap.closest('div.widgetContent');
        $worldmap.vectorMap({
            map: 'world_mill',
            series: {
                regions: [{
                    values: mapData,
                    scale:
                    <?= $data['colour_scale'] ?>, //  gradient blue->green->yellow->red
                    normalizeFunction: 'polynomial'
                }]
            },
            onRegionTipShow: function(e, el, code) {
                var amount = mapData[code] !== undefined ? mapData[code] : 0; // no data defaulted to 0
                el.html(el.html()+' (' + scope + ' - '+amount+')');
            }
        });

        function resizeDashboardWorldMap() {
            var width = $container.width();
            var height = $container.height();
            $worldmap
                .css('width', width + 'px')
                .css('height', height + 'px')
                .vectorMap('get','mapObject').updateSize();
        }
        $(document).ready(function() {
            resizeDashboardWorldMap();
            window.addEventListener("resize", function() {
                if (resize_timeout !== undefined) {
                    clearTimeout(resize_timeout);
                }
                resize_timeout = setTimeout(function() { resizeDashboardWorldMap() }, 500); // redraw after 500ms
            });
            $worldmap.closest('.widgetContentInner').on('widget-resized', function() {
                resizeDashboardWorldMap();
            })
        });
    }());
</script>
