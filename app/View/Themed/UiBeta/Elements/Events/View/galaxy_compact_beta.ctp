<?php
/**
 * Compact Galaxy Tag Element
 *
 * Renders a galaxy as a single compact chip with its cluster members listed inline.
 *
 * Variables:
 * - $galaxyName: string
 * - $clusters: array of GalaxyCluster objects (or at least array with 'value', 'tag_id', etc.)
 * - $preview: bool (optional)
 * - $baseurl: string
 * - $canModify: bool (optional) - whether the user can modify/delete galaxy tags
 * - $canModifyLocal: bool (optional) - whether the user can modify local galaxy tags
 * - $target_type: string (optional) - 'event' or 'attribute'
 * - $target_id: int (optional) - the ID of the event or attribute
 */
?>
<?php if (!empty($clusters)): ?>
    <?php
        usort($clusters, function ($left, $right) {
            $leftValue = is_array($left) ? ($left['value'] ?? '') : (string) $left;
            $rightValue = is_array($right) ? ($right['value'] ?? '') : (string) $right;
            return strcasecmp($leftValue, $rightValue);
        });

        $hash = abs(crc32($galaxyName));
        $hue = $hash % 360;
        $saturation = 55 + ($hash % 3) * 10;
        $bgLightness = 96 - ($hash % 2);
        $borderLightness = 82 - ($hash % 3);
        $textLightness = 28 + ($hash % 3) * 6;
        $labelColor = "hsl($hue, $saturation%, $textLightness%)";
        $bgColor = "hsl($hue, $saturation%, $bgLightness%)";
        $borderColor = "hsl($hue, $saturation%, $borderLightness%)";
        $patternIndex = $hash % 4;

        $canModify = $canModify ?? false;
        $canModifyLocal = $canModifyLocal ?? false;
        $target_type = $target_type ?? null;
        $target_id = $target_id ?? null;
        $visibleCount = 1;
        $hiddenCount = max(0, count($clusters) - $visibleCount);
        $chipId = 'beta-galaxy-chip-' . substr(md5($galaxyName . '|' . serialize(array_column($clusters, 'id'))), 0, 12);
        $galaxyIconClass = 'fas fa-star';
        foreach ($clusters as $cluster) {
            if (!empty($cluster['Galaxy']['icon'])) {
                $galaxyIconClass = $this->FontAwesome->getClass($cluster['Galaxy']['icon']);
                break;
            }
        }
        if ($galaxyIconClass === 'fas fa-star' && !empty($galaxyName)) {
            $Galaxy = ClassRegistry::init('Galaxy');
            $resolvedGalaxy = $Galaxy->find('first', [
                'recursive' => -1,
                'conditions' => ['Galaxy.name' => $galaxyName],
                'fields' => ['Galaxy.icon'],
            ]);
            if (!empty($resolvedGalaxy['Galaxy']['icon'])) {
                $galaxyIconClass = $this->FontAwesome->getClass($resolvedGalaxy['Galaxy']['icon']);
            }
        }
    ?>
    <div class="beta-galaxy-wrapper">
        <div class="beta-galaxy-cluster beta-galaxy-cluster-group" data-pattern="<?php echo $patternIndex; ?>" data-galaxy-chip-id="<?php echo h($chipId); ?>" data-cluster-count="<?php echo (int) count($clusters); ?>" style="background-color: <?php echo $bgColor; ?>; border-color: <?php echo $borderColor; ?>; position: relative; font-size: 13px; line-height: 1.25;">
            <div class="beta-galaxy-header" style="display: flex; align-items: center; gap: 8px;">
                <i class="<?php echo h($galaxyIconClass); ?> beta-galaxy-icon-star" style="color: #000;"></i>
                <span class="beta-galaxy-cluster-label" style="color: <?php echo $labelColor; ?>; font-size: 16px; line-height: 1.1; font-weight: 700;"><?php echo h(strtoupper($galaxyName)); ?></span>
                <?php if ($hiddenCount > 0): ?>
                    <button
                        type="button"
                        class="beta-galaxy-expand-toggle"
                        data-galaxy-expand-toggle
                        data-target-chip="<?php echo h($chipId); ?>"
                        data-hidden-count="<?php echo (int) $hiddenCount; ?>"
                        aria-expanded="false"
                        style="color: <?php echo $labelColor; ?>; margin-left: auto; opacity: 0.85; background: none; border: 0; padding: 0; text-decoration: underline; text-transform: none; font-size: 13px; font-weight: 500; line-height: 1.1; cursor: pointer; white-space: nowrap;"
                    >
                        [+<?php echo (int) $hiddenCount; ?>]
                    </button>
                <?php endif; ?>
            </div>

            <div class="beta-galaxy-cluster-values">
                <?php foreach ($clusters as $index => $cluster): ?>
                    <?php
                        $val = is_array($cluster) ? ($cluster['value'] ?? '') : $cluster;
                        $id = is_array($cluster) ? ($cluster['id'] ?? null) : null;
                        $local = is_array($cluster) ? ($cluster['local'] ?? false) : false;
                        $relBefore = is_array($cluster) ? ($cluster['relationship_type'] ?? null) : null;
                        $relAfter = is_array($cluster) ? ($cluster['relationship'] ?? null) : null;
                        $tagId = is_array($cluster) ? ($cluster['tag_id'] ?? null) : null;
                        $targetTagId = null;
                        if ($target_type && is_array($cluster)) {
                            $targetTagId = $cluster[$target_type . '_tag_id'] ?? null;
                        }

                        $hasUtilityActions = !empty($id) || !empty($tagId);
                        $showEditActions = ($canModify || ($canModifyLocal && $local)) && $target_type && $target_id;
                        $showActions = $hasUtilityActions || $showEditActions;
                        $isCollapsed = $index >= $visibleCount;
                    ?>
                    <span class="beta-galaxy-member<?php echo $isCollapsed ? ' beta-galaxy-member-collapsed' : ''; ?>"<?php echo $isCollapsed ? ' style="display:none; align-items:center;"' : ' style="display:inline-flex; align-items:center;"'; ?>>
                        <span class="beta-galaxy-member-scope" title="<?php echo $local ? __('Local') : __('Public'); ?>">
                            <i class="fas fa-<?php echo $local ? 'user' : 'globe-americas'; ?> beta-galaxy-icon-scope"></i>
                        </span>
                        <?php if ($relBefore): ?>
                            <span class="beta-galaxy-relationship">(<?php echo h($relBefore); ?>)</span>
                        <?php endif; ?>

                        <?php if ($tagId && !empty($baseurl)): ?>
                            <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo intval($tagId); ?>" class="beta-galaxy-link" style="color: <?php echo $labelColor; ?>; font-size: 13px;"><?php echo h($val); ?></a>
                        <?php elseif ($id && !empty($baseurl)): ?>
                            <a href="<?php echo $baseurl; ?>/galaxy_clusters/view/<?php echo h($id); ?>" class="beta-galaxy-link" style="color: <?php echo $labelColor; ?>; font-size: 13px;"><?php echo h($val); ?></a>
                        <?php else: ?>
                            <span style="color: <?php echo $labelColor; ?>; font-size: 13px;"><?php echo h($val); ?></span>
                        <?php endif; ?>

                        <?php if ($relAfter): ?>
                            <span class="beta-galaxy-relationship-after">[<?php echo h($relAfter); ?>]</span>
                        <?php endif; ?>

                        <?php if ($showActions): ?>
                            <span class="beta-galaxy-actions noPrint" style="position: relative; display: inline-flex; align-items: center;">
                                <span class="beta-galaxy-actions-toggle" title="<?php echo __('Actions'); ?>"><i class="fas fa-caret-down"></i></span>
                                <span class="beta-galaxy-actions-dropdown" style="display: none; z-index: 140;">
                                    <?php if ($id): ?>
                                        <a href="<?php echo $baseurl; ?>/galaxy_clusters/view/<?php echo h($id); ?>" class="beta-galaxy-action-item">
                                            <i class="fas fa-sitemap"></i> <?php echo __('View cluster'); ?>
                                        </a>
                                    <?php endif; ?>
                                    <?php if ($tagId): ?>
                                        <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo intval($tagId); ?>" class="beta-galaxy-action-item">
                                            <i class="fas fa-search"></i> <?php echo __('Search similar events'); ?>
                                        </a>
                                    <?php endif; ?>
                                    <?php if ($showEditActions && $target_type !== 'tag_collection' && $targetTagId): ?>
                                        <a href="<?php echo $baseurl; ?>/tags/modifyTagRelationship/<?php echo h($target_type); ?>/<?php echo intval($targetTagId); ?>" class="beta-galaxy-action-item modal-open">
                                            <i class="fas fa-project-diagram"></i> <?php echo __('Modify relationship'); ?>
                                        </a>
                                    <?php endif; ?>
                                    <?php if ($showEditActions && $tagId): ?>
                                        <a href="<?php echo $baseurl; ?>/galaxy_clusters/detach/<?php echo intval($target_id); ?>/<?php echo h($target_type); ?>/<?php echo intval($tagId); ?>"
                                           class="beta-galaxy-action-item beta-galaxy-action-delete"
                                           onclick="confirmClusterDetach(this, '<?php echo h($target_type); ?>', <?php echo intval($target_id); ?>); return false;"
                                           title="<?php echo __('Are you sure you want to detach %s from this %s?', h($val), h($target_type)); ?>">
                                            <i class="fas fa-trash"></i> <?php echo __('Detach'); ?>
                                        </a>
                                    <?php endif; ?>
                                </span>
                            </span>
                        <?php endif; ?>

                    </span>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
<?php endif; ?>
<script>
(function() {
    if (window._galaxyCompactBetaInit) return;
    window._galaxyCompactBetaInit = true;

    function getGalaxyPortalMenu() {
        var $menu = $('#beta-galaxy-actions-portal');
        if (!$menu.length) {
            $menu = $('<div id="beta-galaxy-actions-portal" class="beta-galaxy-actions-dropdown beta-galaxy-actions-portal noPrint"></div>').hide();
            $('body').append($menu);
        }
        return $menu;
    }

    function positionGalaxyPortalMenu($toggle, $menu) {
        var offset = $toggle.offset();
        if (!offset) {
            return;
        }
        $menu.css({display: 'block', visibility: 'hidden'});
        var toggleWidth = $toggle.outerWidth() || 0;
        var toggleHeight = $toggle.outerHeight() || 0;
        var menuWidth = $menu.outerWidth() || 160;
        var menuHeight = $menu.outerHeight() || 0;
        var viewportWidth = $(window).width() || 0;
        var scrollTop = $(window).scrollTop() || 0;
        var viewportBottom = scrollTop + ($(window).height() || 0);
        var left = offset.left + toggleWidth - menuWidth;
        var top = offset.top + toggleHeight + 4;

        if (left < 8) {
            left = 8;
        } else if (viewportWidth && left + menuWidth > viewportWidth - 8) {
            left = Math.max(8, viewportWidth - menuWidth - 8);
        }

        if (top + menuHeight > viewportBottom - 8) {
            top = offset.top - menuHeight - 4;
        }
        if (top < scrollTop + 8) {
            top = scrollTop + 8;
        }

        $menu.css({
            position: 'absolute',
            top: top,
            left: left,
            right: 'auto',
            bottom: 'auto',
            zIndex: 10050,
            visibility: 'visible'
        });
    }

    function closeGalaxyActionMenus() {
        $('.beta-galaxy-actions.open').removeClass('open');
        $('.beta-galaxy-wrapper').removeClass('beta-galaxy-wrapper-active');
        $('.beta-galaxy-member').css('z-index', '');
        $('.beta-galaxy-cluster').css('z-index', '');
        $('.col-clusters').css('z-index', '');
        $('.beta-events-table tr').css({'z-index': '', 'position': ''});
        getGalaxyPortalMenu().hide().empty().removeData('sourceActions');
    }

    function setGalaxyChipExpanded($chip, shouldExpand) {
        var $toggle = $chip.find('[data-galaxy-expand-toggle]').first();
        if (!$toggle.length) {
            return;
        }
        var hiddenCount = parseInt($toggle.data('hidden-count'), 10) || 0;
        var $hiddenMembers = $chip.find('.beta-galaxy-member-collapsed');

        if (shouldExpand) {
            $hiddenMembers.css('display', 'inline-flex');
            $toggle.attr('aria-expanded', 'true').text('[-]');
        } else {
            $hiddenMembers.hide();
            $toggle.attr('aria-expanded', 'false').text('[+' + hiddenCount + ']');
        }
    }

    function syncGalaxyExpandAllToggle() {
        var $globalToggle = $('#beta-galaxies-expand-all-toggle');
        if (!$globalToggle.length) {
            return;
        }
        var $chipToggles = $('#galaxies_div [data-galaxy-expand-toggle]');
        if (!$chipToggles.length) {
            $globalToggle.hide();
            return;
        }
        var allExpanded = true;
        $chipToggles.each(function() {
            if ($(this).attr('aria-expanded') !== 'true') {
                allExpanded = false;
                return false;
            }
        });
        $globalToggle.text(allExpanded ? '<?php echo h(__('Contract all')); ?>' : '<?php echo h(__('Expand all')); ?>').show();
    }

    window.betaSetAllGalaxyChipsExpanded = function(shouldExpand) {
        $('#galaxies_div .beta-galaxy-cluster').each(function() {
            setGalaxyChipExpanded($(this), shouldExpand);
        });
        if (!shouldExpand) {
            closeGalaxyActionMenus();
        }
        syncGalaxyExpandAllToggle();
    };

    $(document).on('click', '#beta-galaxies-expand-all-toggle', function(e) {
        e.preventDefault();
        var shouldExpand = $(this).text().trim() === '<?php echo h(__('Expand all')); ?>';
        window.betaSetAllGalaxyChipsExpanded(shouldExpand);
    });

    $(document).on('click', '.beta-galaxy-actions-toggle', function(e) {
        e.stopPropagation();
        e.preventDefault();
        var $actions = $(this).closest('.beta-galaxy-actions');
        var $member = $(this).closest('.beta-galaxy-member');
        var $chip = $(this).closest('.beta-galaxy-cluster');
        var $wrapper = $(this).closest('.beta-galaxy-wrapper');
        var $dropdown = $actions.find('.beta-galaxy-actions-dropdown').first();
        var $portalMenu = getGalaxyPortalMenu();
        var wasOpen = $actions.hasClass('open');
        closeGalaxyActionMenus();
        if (!wasOpen) {
            $actions.addClass('open');
            $wrapper.addClass('beta-galaxy-wrapper-active');
            $member.css('z-index', '120');
            $chip.css('z-index', '110');
            $chip.closest('.col-clusters').css({'position': 'relative', 'z-index': '130'});
            $chip.closest('tr').css({'position': 'relative', 'z-index': '131'});
            $portalMenu.html($dropdown.html()).data('sourceActions', $actions.get(0));
            positionGalaxyPortalMenu($(this), $portalMenu);
        }
    });

    $(window).on('resize scroll', function() {
        var $portalMenu = $('#beta-galaxy-actions-portal');
        if (!$portalMenu.length || !$portalMenu.is(':visible')) {
            return;
        }
        var sourceActions = $portalMenu.data('sourceActions');
        if (!sourceActions) {
            return;
        }
        var $toggle = $(sourceActions).find('.beta-galaxy-actions-toggle').first();
        if ($toggle.length) {
            positionGalaxyPortalMenu($toggle, $portalMenu);
        }
    });

    $(document).on('click', '[data-galaxy-expand-toggle]', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var $toggle = $(this);
        var chipId = $toggle.data('target-chip');
        var $chip = $('[data-galaxy-chip-id="' + chipId + '"]');
        var expanded = $toggle.attr('aria-expanded') === 'true';

        if (expanded) {
            setGalaxyChipExpanded($chip, false);
            closeGalaxyActionMenus();
        } else {
            setGalaxyChipExpanded($chip, true);
        }
        syncGalaxyExpandAllToggle();
    });

    $(document).on('click', function(e) {
        if (!$(e.target).closest('.beta-galaxy-actions').length) {
            closeGalaxyActionMenus();
        }
    });

    $(document).on('keydown', function(e) {
        if (e.key === 'Escape') {
            closeGalaxyActionMenus();
        }
    });

    syncGalaxyExpandAllToggle();
})();
</script>
