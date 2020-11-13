<?php
/*
 * create single view child index
 *
 */
    $randomId = bin2hex(openssl_random_pseudo_bytes(8));
    if (!empty($child['url_params'])) {
        if (!is_array($child['url_params'])) {
            $child['url_params'] = [$child['url_params']];
        }
        foreach ($child['url_params'] as $i => $url_param) {
            $child['url'] = str_replace('{{' . $i . '}}', $this->Hash->extract($data, $url_param)[0], $child['url']);
        }
    }
    echo sprintf(
        '<div class="card">%s%s</div>',
        sprintf(
            '<div class="card-header" id="heading-%s"><h5 class="mb0">%s</h5></div>',
            $randomId,
            sprintf(
                '<button class="btn btn-link" data-toggle="collapse" data-target="#view-child-%s" aria-expanded="true" aria-controls="collapseOne">%s</button>',
                $randomId,
                h($child['title'])
            )
        ),
        sprintf(
            '<div class="collapse %s" id="view-child-%s" data-parent="#accordion" labelledby="heading-%s"><div id="view-child-body-%s" class="card-body" data-content-url="%s" data-load-on="%s"></div></div>',
            !empty($child['collapsed']) ? 'show' : 'collapsed',
            $randomId,
            $randomId,
            $randomId,
            h($child['url']),
            empty($child['loadOn']) ? 'ready' : h($child['loadOn'])
        )
    );
?>
<script type="text/javascript">
    $(document).ready(function() {
        var url = $('#view-child-body-<?= h($randomId) ?>').data('content-url');
        var loadon  = $('#view-child-body-<?= h($randomId) ?>').data('load-on');
        if (loadon === 'ready') {
            $.ajax({
                success:function (data, textStatus) {
                    $('#view-child-body-<?= h($randomId) ?>').html(data);
                },
                type: "get",
                cache: false,
                url: url,
            });
        } else {
            $('#view-child-<?= h($randomId) ?>').on('hidden.bs.collapse', function () {
                $.ajax({
                    success:function (data, textStatus) {
                        $('#view-child-body-<?= h($randomId) ?>').html(data);
                    },
                    type: "get",
                    cache: false,
                    url: url,
                });
            })
        }
    });
</script>
