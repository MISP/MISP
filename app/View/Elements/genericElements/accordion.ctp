<?php
    if (empty($elementId)) {
        $elementId = 'accordion-' . dechex(mt_rand());
    }
    $elements = [];
    $url = $baseurl . $url;
    echo sprintf(
        '<div class="accordion" id="%s"><div class="accordion-group">%s%s</div></div>',
        h($elementId),
        sprintf(
            '<div class="accordion-heading">
                <span class="accordion-toggle blue bold" data-toggle="collapse" data-parent="#%s" href="#%s" >%s %s</span>
            </div>',
            h($elementId),
            h($elementId) . '-collapse',
            !empty($titleHTML) ? $titleHTML : h($title),
            !empty($allowFullscreen) ? '' : sprintf(
                '<span class="fas fa-external-link-alt" title="View %s full screen" onclick="event.stopPropagation(); window.location.href=\'%s\';"></span>',
                h($title),
                h($url)
            )
        ),
        sprintf(
            '<div id="%s" class="accordion-body collapse"><div id="%s" class="accordion-inner" data-url="%s">&nbsp;</div></div>',
            h($elementId) . '-collapse',
            h($elementId) . '-collapse-inner',
            h($url)
        )
    );
?>
<script type="text/javascript">
    $(function() {
        var elementId = '#<?= h($elementId) ?>';
        $(elementId).on('shown', function() {
            $.ajax({
                type:"get",
                url: $(elementId + '-collapse-inner').data('url'),
                beforeSend: function() {
                    $(".loading").show();
                },
                success: function(data) {
                    $(elementId + '-collapse-inner').html(data);
                },
                error: function() {
                    showMessage('fail', 'Something went wrong - could not fetch content.');
                },
                complete: function() {
                    $(".loading").hide();
                }
            });
        });
    });
</script>
