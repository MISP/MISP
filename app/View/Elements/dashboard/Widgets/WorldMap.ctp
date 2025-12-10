<?php
$css_collection = ['jquery-jvectormap-2.0.5'];
$js_collection  = ['jquery-jvectormap-2.0.5.min', 'jquery-jvectormap-world-mill'];

echo $this->element('genericElements/assetLoader', [
    'css'  => $css_collection,
    'js'   => $js_collection,
    'meta' => 'icon'
]);

$randomNumber = rand();

if (!empty($config['widget_config']['colour_scale'])) {
    $data['colour_scale'] = json_encode($config['widget_config']['colour_scale']);
} else {
    $data['colour_scale'] =
        '["#2fa1db","#3e95cd","#4689c0","#4b7eb4","#4d73a8","#4e679c","#4d5b90","#4b4f85","#494279","#45346f","#402464","#3c0f59"]';
}
?>
<div id="world-map-<?= $randomNumber ?>" class="worldmap-container"></div>

<script>
(function() {
    const id          = "world-map-<?= $randomNumber ?>";
    const scope       = "<?= h($data['scope']) ?>";
    const mapData     = <?= json_encode($data['data']); ?>;
    const colourScale = <?= $data['colour_scale'] ?>;

    const $map       = $("#" + id);
    const $container = $map.closest(".widgetContent");

    function syncContainerSize() {
        const w = $container.width();
        const h = $container.height();
        if (!w || !h) return null;
        $map.css({ width: w, height: h });
        return { w, h };
    }

    function resizeSvgOnly() {
        const dims = syncContainerSize();
        if (!dims) return;
        const svg = $map.find("svg")[0];
        if (!svg) return;
        svg.setAttribute("width",  dims.w);
        svg.setAttribute("height", dims.h);
        const mapObj = $map.data("mapObject");
        if (mapObj && typeof mapObj.updateSize === "function") {
            mapObj.updateSize();
        }
    }

    function initMap() {
        const dims = syncContainerSize();
        if (!dims) {
            setTimeout(initMap, 50);
            return;
        }

        $map.vectorMap({
            map: "world_mill",
            series: {
                regions: [{
                    values: mapData,
                    scale: colourScale,
                    normalizeFunction: "polynomial"
                }]
            },
            onRegionTipShow: function(e, el, code) {
                const amount = mapData[code] ?? 0;
                el.html(el.html() + " (" + htmlEncode(scope) + " - " + amount + ")");
            }
        });

        resizeSvgOnly();
    }

    function handleResize() {
        resizeSvgOnly();
    }

    $(function() {
        setTimeout(initMap, 80);
        $container.on("widget-resized", handleResize);
        $(window).on("resize", handleResize);
    });
}());
</script>

<style>
#<?= "world-map-".$randomNumber ?> {
    width: 100% !important;
    height: 100% !important;
}

#<?= "world-map-".$randomNumber ?> svg {
    width: 100% !important;
    height: 100% !important;
    max-height: none !important;
}
</style>
