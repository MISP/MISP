<?php
    if (empty($elementId)) {
        $elementId = 'accordion-' . bin2hex(openssl_random_pseudo_bytes(8));
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
            h($title),
            !empty($allowFullscreen) ? '' : sprintf(
                '<span class="fas fa-external-link-alt" title="View %s full screen" onClick="window.location.href=\'%s\';"></span>',
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
    $(document).ready(function() {
        var elementId = '#<?= h($elementId) ?>';
        $(elementId).on('shown', function() {
            $.ajax({
                type:"get",
                url: $(elementId + '-collapse-inner').data('url'),
                beforeSend: function (XMLHttpRequest) {
                    $(".loading").show();
                },
                success:function (data) {
                    $(elementId + '-collapse-inner').html(data);
                    $(".loading").hide();
                },
                error:function() {
                    showMessage('fail', 'Something went wrong - could not fetch content.');
                }
            });
        });
    });
</script>
