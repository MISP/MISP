<?php
if (!function_exists('getResolvableID')) {
    function getResolvableID($sectionName, $panelName = false)
    {
        $id = sprintf('sp-%s', preg_replace('/(\.|\W)/', '_', h($sectionName)));
        if (!empty($panelName)) {
            $id .= '-' . preg_replace('/(\.|\W)/', '_', h($panelName));
        }
        return $id;
    }
}
?>

<nav id="navbar-scrollspy-setting" class="navbar">
    <nav class="nav nav-pills flex-column">
        <?php foreach ($groupedSetting as $group => $sections): ?>
            <a class="nav-link main-group text-reset p-1" href="#<?= getResolvableID($group) ?>"><?= h($group) ?></a>
                <nav class="nav nav-pills sub-group collapse flex-column" data-maingroup="<?= getResolvableID($group) ?>">
                    <?php foreach ($sections as $section): ?>
                        <a class="nav-link nav-link-group text-reset ms-3 my-1 p-1" href="#<?= getResolvableID($group, $section) ?>"><?= h($section) ?></a>
                    <?php endforeach; ?>
                </nav>
            </a>
        <?php endforeach; ?>
    </nav>
</nav>

<script>
    $(document).ready(function() {
        $('[data-bs-spy="scroll"]').on('activate.bs.scrollspy', function({relatedTarget}) {
            const $associatedLink = $(`#navbar-scrollspy-setting nav.nav-pills .nav-link[href="${relatedTarget}"]`)
            let $associatedNav
            if ($associatedLink.hasClass('main-group')) {
                $associatedNav = $associatedLink.next()
            } else {
                $associatedNav = $associatedLink.parent()
            }
            const $allNavs = $('#navbar-scrollspy-setting nav.nav-pills.sub-group')
            $allNavs.removeClass('group-active').hide()
            $associatedNav.addClass('group-active').show()
        })
    })
</script>

<style>
    #navbar-scrollspy-setting nav.nav-pills .nav-link {
        background-color: unset !important;
        color: black;
        display: block;
    }

    #navbar-scrollspy-setting nav.nav-pills .nav-link:not(.main-group).active {
        color: #007bff !important;
        font-weight: bold;
    }

    #navbar-scrollspy-setting nav.nav-pills .nav-link.main-group:before {
        margin-right: 0.25em;
        font-family: 'Font Awesome 5 Free';
        font-weight: 900;
        -webkit-font-smoothing: antialiased;
        display: inline-block;
        font-style: normal;
        font-variant: normal;
        text-rendering: auto;
        line-height: 1;
    }

    #navbar-scrollspy-setting nav.nav-pills .nav-link.main-group.active:before {
        content: "\f0d7";
    }

    #navbar-scrollspy-setting nav.nav-pills .nav-link.main-group:before {
        content: "\f0da";
    }
</style>