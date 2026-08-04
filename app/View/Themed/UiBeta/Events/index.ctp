<?php
/**
 * Beta version of Events/index view
 * 
 * Changes from standard version:
 * - No left sidebar navigation
 * - Added "Create Event" button with dropdown for "Create event from import"
 * - Added "Event Collections" link
 * 
 * @since 2.5.x (beta)
 */
?>
<style>
    .beta-event-list-bulk-actions-bar {
        display: none;
        padding: 10px 14px;
        border: 1px solid #d9e5f2;
        border-radius: 8px 8px 0 0;
        background: linear-gradient(180deg, #f8fbff 0%, #eef5fc 100%);
        position: fixed;
        left: 24px;
        right: 24px;
        bottom: 0;
        z-index: 1100;
        box-shadow: 0 -4px 16px rgba(80, 108, 140, 0.14);
    }
    .beta-event-list-bulk-actions-bar.is-visible {
        display: block;
    }
    .beta-event-list-bulk-actions-bar-inner {
        display: flex;
        align-items: center;
        gap: 12px;
        justify-content: space-between;
    }
    .beta-event-list-bulk-actions-summary {
        font-size: 13px;
        font-weight: 600;
        color: #36506b;
        white-space: nowrap;
    }
    .beta-event-list-bulk-actions-buttons {
        display: inline-flex;
        align-items: center;
        justify-content: flex-end;
        gap: 8px;
        flex: 1 1 auto;
        flex-wrap: wrap;
    }
    .beta-event-list-bulk-actions-group {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }
    .beta-event-list-bulk-actions-group.beta-event-list-bulk-actions-group-danger {
        margin-left: auto;
    }
    .beta-event-list-bulk-actions-bar .btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    body.beta-event-list-bulk-actions-visible {
        padding-bottom: 84px;
    }
    @media (max-width: 767px) {
        .beta-event-list-bulk-actions-bar {
            left: 12px;
            right: 12px;
            bottom: 0;
            padding-bottom: calc(10px + env(safe-area-inset-bottom, 0px));
        }
        .beta-event-list-bulk-actions-bar-inner {
            flex-direction: column;
            align-items: stretch;
            gap: 12px;
        }
        .beta-event-list-bulk-actions-buttons,
        .beta-event-list-bulk-actions-group {
            width: 100%;
            justify-content: stretch;
        }
        .beta-event-list-bulk-actions-group.beta-event-list-bulk-actions-group-danger {
            margin-left: 0;
        }
        .beta-event-list-bulk-actions-bar .btn {
            justify-content: center;
            flex: 1 1 auto;
        }
        body.beta-event-list-bulk-actions-visible {
            padding-bottom: 132px;
        }
    }
</style>
<div class="events <?php if (!$ajax) echo 'index'; ?> beta-events-index" style="padding-bottom: 96px;">
    <?php
        $searchScopes = [
            'searcheventinfo' => __('Event info'),
            'searchall' => __('All fields'),
            'searcheventid' => __('ID / UUID'),
            'searchtags' => __('Tag'),
        ];
        $searchKey = 'searcheventinfo';

        $filterParamsString = [];
        foreach ($passedArgsArray as $k => $v) {
            if (isset($searchScopes["search$k"])) {
                $searchKey = "search$k";
            }

            $filterParamsString[] = sprintf(
                '%s: %s',
                h(ucfirst($k)),
                h(is_array($v) ? http_build_query($v) : $v)
            );
        }
        $filterParamsString = implode(' & ', $filterParamsString);

        $columnsDescription = [
            'owner_org' => __('Owner org'),
            'is_extension' => __('Extended event'),
            'attribute_count' => __('Attribute count'),
            'creator_user' => __('Creator user'),
            'tags' => __('Tags'),
            'highlights' => __('Highlight tags'),
            'clusters' => __('Clusters'),
            'correlations' => __('Correlations'),
            'sightings' => __('Sightings'),
            'proposals' => __('Proposals'),
            'discussion' => __('Posts'),
            'report_count' => __('Report count'),
            'timestamp' => __('Last modified at'),
            'publish_timestamp' => __('Published at')
        ];

        $columnsMenu = [];
        foreach ($possibleColumns as $possibleColumn) {
            $html = in_array($possibleColumn, $columns, true) ? '<i class="fa fa-check"></i> ' : '<i class="fa fa-check" style="visibility: hidden"></i> ';
            $html .= $columnsDescription[$possibleColumn];
            $columnsMenu[] = [
                'html' => $html,
                'onClick' => 'eventIndexColumnsToggle',
                'onClickParams' => [$possibleColumn],
            ];
        }
    ?>
    <div class="beta-events-header-row">
        <div class="beta-header-left">
            <h2><?php echo __('Events');?></h2>
            <div class="beta-header-filters">
                <?php if ($this->Acl->canAccess('events', 'add')): ?>
                    <div class="btn-group beta-create-event-group">
                        <a href="<?= $baseurl ?>/events/add" class="btn btn-primary">
                            <i class="fa fa-plus"></i> <?= __('Create Event') ?>
                        </a>
                        <button type="button" class="btn btn-primary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                            <span class="caret"></span>
                            <span class="sr-only"><?= __('Toggle Dropdown') ?></span>
                        </button>
                        <ul class="dropdown-menu">
                            <li><a href="<?= $baseurl ?>/events/add_misp_export"><i class="fa fa-file-import"></i> <?= __('Create event from import') ?></a></li>
                            <?php if ($this->Acl->canAccess('eventTemplates', 'index') && $this->Acl->canAccess('eventTemplates', 'instantiate')): ?>
                                <li><a href="#" onclick="event.preventDefault();openEventTemplatePicker();"><i class="fa fa-clone"></i> <?= __('Create event from template') ?></a></li>
                            <?php endif; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                <a href="<?= $baseurl ?>/collections/index" class="btn btn-default beta-filter-button">
                    <i class="fa fa-folder-open"></i> <?= __('Event Collections') ?>
                </a>
                <button class="btn btn-default beta-filter-button searchFilterButton" title="<?= __('My events only') ?>" data-searchemail="<?= h($me['email']) ?>">
                    <?= __('My Events') ?>
                </button>
                <button class="btn btn-default beta-filter-button searchFilterButton" title="<?= __('My organisation\'s events only') ?>" data-searchorg="<?= h($me['org_id']) ?>">
                    <?= __('Org Events') ?>
                </button>
            </div>
        </div>
        <div class="beta-columns-control">
            <div class="btn-group">
                <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" title="<?= __('Choose columns to show') ?>">
                    <i class="fa fa-columns"></i> <?= __('Columns') ?> <span class="caret"></span>
                </button>
                <ul class="dropdown-menu dropdown-menu-right beta-columns-menu">
                    <?php foreach ($possibleColumns as $possibleColumn): ?>
                        <li>
                            <a href="#" onclick="eventIndexColumnsToggle('<?= h($possibleColumn) ?>'); return false;">
                                <i class="fa fa-check" style="<?= in_array($possibleColumn, $columns, true) ? '' : 'visibility: hidden' ?>"></i>
                                <?= h($columnsDescription[$possibleColumn]) ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <div class="beta-search-row">
        <div class="beta-search-controls">
            <div class="beta-search-label"><?= __('Search') ?></div>
            <div class="beta-search-input-group">
                <select id="quickFilterScopeSelector" class="form-control beta-search-scope">
                    <?php foreach ($searchScopes as $key => $value): ?>
                        <option value="<?= h($key) ?>" <?= $searchKey === $key ? 'selected' : '' ?>><?= h($value) ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="text" id="quickFilterField" class="form-control beta-search-input" placeholder="<?= __('Enter value to search') ?>" data-searchkey="<?= h($searchKey) ?>">
                <button id="quickFilterButton" class="btn btn-primary beta-search-button"><?= __('Filter') ?></button>
                <?php /* json_encode emits a properly-escaped JS string literal; h() then guards the
                       attribute layer. Plain h($urlparams) inside a single-quoted JS string is unsafe
                       here: the browser HTML-decodes the onclick value before JS parsing, restoring any
                       &#039; and allowing a crafted searcheventinfo value to break out (XSS). */ ?>
                <button class="btn btn-default beta-advanced-filter-button" onclick="getPopup(<?= h(json_encode($urlparams)) ?>, 'events', 'filterEventIndex')">
                    <i class="fa fa-search"></i> <?= __('Advanced Filter...') ?>
                </button>
            </div>
        </div>

    </div>
    <div class="beta-column-overflow-notice hidden" aria-live="polite"></div>
    <?php if (count($passedArgsArray) > 0): ?>
        <div class="beta-active-filters">
            <span class="bold"><?= __('Filters') ?>:</span> <?= h($filterParamsString) ?>
            <a href="<?= $baseurl ?>/events/index" class="btn btn-xs btn-default" title="<?= __('Remove filters') ?>">
                <i class="fa fa-times"></i> <?= __('Clear') ?>
            </a>
        </div>
    <?php 
    endif;
        echo $this->element('Events/eventIndexTable');
    ?>
    <div id="beta-event-list-bulk-actions-bar" class="beta-event-list-bulk-actions-bar" aria-hidden="true">
        <div class="beta-event-list-bulk-actions-bar-inner">
            <div class="beta-event-list-bulk-actions-summary">
                <span id="beta-event-list-selected-count">0</span> <?= __('selected'); ?>
            </div>
            <div class="beta-event-list-bulk-actions-buttons">
                <div class="beta-event-list-bulk-actions-group">
                    <button id="multi-export-button" type="button" class="btn btn-default mass-export" onclick="multiSelectExportEvents(); return false;" title="<?= __('Export selected events') ?>">
                        <i class="fa fa-file-export"></i> <?= __('Export'); ?>
                    </button>
                    <?php if ($this->Acl->canAccess('collectionElements', 'addElementToCollection')): ?>
                    <button id="multi-collection-button" type="button" class="btn btn-default mass-collection" onclick="openAddSelectedEventsToCollectionModal(); return false;" title="<?= __('Add selected events to a collection') ?>">
                        <i class="fa fa-folder-plus"></i> <?= __('Add to Collection'); ?>
                    </button>
                    <?php endif; ?>
                </div>
                <div class="beta-event-list-bulk-actions-group beta-event-list-bulk-actions-group-danger">
                    <button id="multi-delete-button" type="button" class="btn btn-danger mass-delete" onclick="multiSelectDeleteEvents(); return false;" title="<?= __('Delete selected events') ?>">
                        <i class="fa fa-trash"></i> <?= __('Delete'); ?>
                    </button>
                </div>
            </div>
        </div>
    </div>
    <div class="beta-pagination-bottom">
        <p>
        <?php
        echo $this->Paginator->counter(array(
        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
        ));
        ?>
        </p>
        <div class="pagination">
            <ul>
            <?php
                $pagination = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                $pagination .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                $pagination .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
                echo $pagination;
            ?>
            </ul>
        </div>
    </div>
</div>
<script>
    var passedArgsArray = <?php echo $passedArgs; ?>;
    var betaEventsIndexBaseurl = <?php echo json_encode($baseurl); ?>;
    var betaViewCollectionLabel = <?php echo json_encode(__('View collection')); ?>;
    var betaColumnDescriptions = <?php echo json_encode($columnsDescription); ?>;
    var betaColumnPriority = <?php echo json_encode([
        'creator_user',
        'publish_timestamp',
        'timestamp',
        'discussion',
        'proposals',
        'sightings',
        'report_count',
        'correlations',
        'highlights',
        'attribute_count',
        'tags',
        'clusters',
        'owner_org',
        'is_extension',
    ]); ?>;

    window.eventCollectionContext = null;

    function getSelectedEventIds() {
        var selected = [];
        $('.select:checked').each(function() {
            var eventId = $(this).data('id');
            if (eventId != null) {
                selected.push(parseInt(eventId, 10));
            }
        });
        return selected;
    }

    function getSelectedEventUuids() {
        var selectedUuids = [];
        $('.select:checked').each(function() {
            var eventId = $(this).data('id');
            if (eventId == null) {
                return;
            }

            var container = getEventCollectionsContainer(eventId);
            var eventUuid = container ? container.getAttribute('data-event-uuid') : null;
            if (eventUuid) {
                selectedUuids.push(String(eventUuid));
            }
        });
        return selectedUuids;
    }

    window.updateBetaEventListBulkActions = function() {
        var selectedCount = $('.select:checked').length;
        var deletableCount = $('.select:checked[data-can-modify="1"]').length;
        var $bar = $('#beta-event-list-bulk-actions-bar');

        $('#beta-event-list-selected-count').text(selectedCount);
        $bar.toggleClass('is-visible', selectedCount > 0);
        $bar.attr('aria-hidden', selectedCount > 0 ? 'false' : 'true');
        $('body').toggleClass('beta-event-list-bulk-actions-visible', selectedCount > 0);

        $('#multi-delete-button').prop('disabled', deletableCount === 0);
    };

    $(document)
        .off('change.betaEventBulkActions', '.select')
        .on('change.betaEventBulkActions', '.select', function() {
            window.updateBetaEventListBulkActions();
        });

    function syncSelectedEventCollectionFields($form, eventUuids) {
        if (!$form || !$form.length || !Array.isArray(eventUuids) || eventUuids.length === 0) {
            return;
        }

        $form.find('input[name="data[CollectionElement][element_uuid][]"]').remove();
        eventUuids.forEach(function(eventUuid) {
            $('<input>', {
                type: 'hidden',
                name: 'data[CollectionElement][element_uuid][]',
                value: eventUuid
            }).appendTo($form);
        });
    }

    window.syncSelectedEventCollectionFields = syncSelectedEventCollectionFields;

    window.openAddSelectedEventsToCollectionModal = function() {
        var selectedEventUuids = getSelectedEventUuids();
        if (selectedEventUuids.length === 0) {
            return false;
        }

        window.eventCollectionContext = {
            eventUuids: selectedEventUuids,
            eventIds: getSelectedEventIds()
        };
        openGenericModal(
            betaEventsIndexBaseurl + '/collectionElements/addElementToCollection/Event/' + encodeURIComponent(selectedEventUuids[0]),
            undefined,
            function() {
                var $form = $('#genericModal .genericForm');
                if (!$form.length) {
                    return;
                }

                syncSelectedEventCollectionFields($form, selectedEventUuids);
            }
        );
        return false;
    };

    function getEventCollectionsContainer(eventId) {
        return document.getElementById('event-collections-container-' + eventId);
    }

    function buildCollectionChip(collection) {
        var collectionType = (collection && collection.type) ? String(collection.type) : 'other';
        var collectionTypeClass = collectionType.replace(/[^a-z0-9_-]/gi, '');
        var collectionDescription = collection && collection.description ? String(collection.description).substring(0, 80) : '';
        var link = document.createElement('a');

        link.href = betaEventsIndexBaseurl + '/collections/view/' + encodeURIComponent(collection.id);
        link.className = 'beta-collection-chip beta-type-' + collectionTypeClass;
        link.title = collectionType + (collectionDescription ? ': ' + collectionDescription : '');
        link.setAttribute('aria-label', betaViewCollectionLabel + ' ' + ((collection && collection.name) || ''));

        var icon = document.createElement('i');
        icon.className = 'fa fa-folder';
        icon.style.fontSize = '10px';
        icon.style.marginRight = '3px';
        link.appendChild(icon);
        link.appendChild(document.createTextNode(collection && collection.name ? String(collection.name) : ''));

        return link;
    }

    function renderEventCollections(container, collections) {
        container.innerHTML = '';
        if (!Array.isArray(collections) || collections.length === 0) {
            return;
        }

        var chips = document.createElement('div');
        chips.className = 'beta-event-collections-chips';

        collections.forEach(function(collection) {
            chips.appendChild(buildCollectionChip(collection));
        });
        container.appendChild(chips);
    }

    function applyCollectionsToContainer(container, data) {
        if (!container) {
            return;
        }

        var eventUuid = container.getAttribute('data-event-uuid');
        var collections = data && typeof data === 'object' && eventUuid && Array.isArray(data[eventUuid]) ? data[eventUuid] : [];
        renderEventCollections(container, collections);
        container.setAttribute('data-collections-loaded', '1');
    }

    function loadCollectionsForContainers(containers, forceReload) {
        var uuids = [];

        containers.forEach(function(container) {
            if (!container) {
                return;
            }

            if (forceReload) {
                container.removeAttribute('data-collections-loaded');
            }

            if (container.getAttribute('data-collections-loaded') === '1') {
                return;
            }

            var eventUuid = container.getAttribute('data-event-uuid');
            if (!eventUuid) {
                return;
            }

            container.setAttribute('data-collections-loaded', 'loading');
            if (uuids.indexOf(eventUuid) === -1) {
                uuids.push(eventUuid);
            }
        });

        if (uuids.length === 0) {
            return;
        }

        $.ajax({
            url: betaEventsIndexBaseurl + '/collections/getCollectionsForElements/Event.json',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ uuids: uuids }),
            dataType: 'json',
            success: function(data) {
                containers.forEach(function(container) {
                    applyCollectionsToContainer(container, data);
                });
            },
            error: function() {
                containers.forEach(function(container) {
                    if (container) {
                        container.removeAttribute('data-collections-loaded');
                    }
                });
            }
        });
    }

    function loadVisibleEventCollections() {
        var containers = [];
        $('[id^="event-collections-container-"]').each(function() {
            containers.push(this);
        });
        loadCollectionsForContainers(containers);
    }

    window.openAddToCollectionModal = function(eventUuid, eventId) {
        window.eventCollectionContext = {
            eventUuid: eventUuid,
            eventId: parseInt(eventId, 10)
        };
        openGenericModal(betaEventsIndexBaseurl + '/collectionElements/addElementToCollection/Event/' + encodeURIComponent(eventUuid));
    };

    window.loadEventCollections = function(forceReload) {
        var context = window.eventCollectionContext;
        if (!context) {
            return;
        }

        if ((!Array.isArray(context.eventUuids) || context.eventUuids.length === 0) && Array.isArray(context.eventIds) && context.eventIds.length > 0) {
            context.eventUuids = [];
            context.eventIds.forEach(function(eventId) {
                var container = getEventCollectionsContainer(eventId);
                if (!container) {
                    return;
                }
                var eventUuid = container.getAttribute('data-event-uuid');
                if (eventUuid) {
                    context.eventUuids.push(String(eventUuid));
                }
            });
        }

        if (Array.isArray(context.eventUuids) && context.eventUuids.length > 0) {
            var containersByUuid = {};
            $('[id^="event-collections-container-"]').each(function() {
                var eventUuid = this.getAttribute('data-event-uuid');
                if (eventUuid) {
                    containersByUuid[eventUuid] = this;
                }
            });

            var containers = [];
            context.eventUuids.forEach(function(eventUuid) {
                var container = containersByUuid[eventUuid];
                if (container) {
                    containers.push(container);
                }
            });
            if (containers.length > 0) {
                loadCollectionsForContainers(containers, !!forceReload);
            }
            window.eventCollectionContext = null;
            return;
        }

        if (!context.eventUuid || !context.eventId) {
            return;
        }

        var container = getEventCollectionsContainer(context.eventId);
        if (!container) {
            window.eventCollectionContext = null;
            return;
        }

        loadCollectionsForContainers([container], !!forceReload);
        window.eventCollectionContext = null;
    };

    function fadeOutOverflowNotice(notice) {
        window.setTimeout(function() {
            notice.classList.add('beta-column-overflow-notice-fading');
            window.setTimeout(function() {
                notice.classList.add('hidden');
                notice.classList.remove('beta-column-overflow-notice-fading');
                notice.innerHTML = '';
            }, 400);
        }, 5000);
    }

    function updateOverflowNotice(hiddenColumns) {
        var notice = document.querySelector('.beta-column-overflow-notice');
        if (!notice) {
            return;
        }
        if (!hiddenColumns.length) {
            notice.classList.add('hidden');
            notice.classList.remove('beta-column-overflow-notice-fading');
            notice.innerHTML = '';
            return;
        }

        var labels = hiddenColumns.map(function(columnName) {
            return betaColumnDescriptions[columnName] || columnName;
        });
        notice.innerHTML = '<i class="fa fa-columns"></i>' +
            <?= json_encode(__('Some selected columns were hidden to keep the table on-screen:')) ?> +
            ' ' + labels.join(', ') + '. ' +
            <?= json_encode(__('Use the "Columns" button to customise your columns.')) ?>;
        notice.classList.remove('hidden', 'beta-column-overflow-notice-fading');
        fadeOutOverflowNotice(notice);
    }

    function resetAutoHiddenColumns(table) {
        betaColumnPriority.forEach(function(columnName) {
            table.find('[data-beta-column="' + columnName + '"]').removeClass('beta-column-auto-hidden');
        });
    }

    function fitBetaEventColumns() {
        var $table = $('.beta-events-table').first();
        if (!$table.length) {
            return;
        }

        var table = $table;
        var container = $table.parent();
        var hiddenColumns = [];
        resetAutoHiddenColumns(table);

        betaColumnPriority.forEach(function(columnName) {
            var $cells = table.find('[data-beta-column="' + columnName + '"]');
            if (!$cells.length) {
                return;
            }
            if ($cells.filter(':visible').length === 0) {
                return;
            }
            if ($table[0].scrollWidth <= container[0].clientWidth) {
                return;
            }
            $cells.addClass('beta-column-auto-hidden');
            hiddenColumns.push(columnName);
        });

        updateOverflowNotice(hiddenColumns);
    }

    var fitBetaEventColumnsDebounced = (function() {
        var timer = null;
        return function() {
            if (timer !== null) {
                window.clearTimeout(timer);
            }
            timer = window.setTimeout(function() {
                timer = null;
                fitBetaEventColumns();
            }, 80);
        };
    }());

    $(function() {
        fitBetaEventColumns();
        $(window).on('resize', fitBetaEventColumnsDebounced);

        $('.searchFilterButton').click(function() {
            runIndexFilter(this);
        });
        $('#quickFilterScopeSelector').change(function() {
            $('#quickFilterField').data('searchkey', this.value)
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
        loadVisibleEventCollections();
    });
</script>
<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['vis', 'distribution-graph'],
    'js' => ['vis', 'jquery-ui.min', 'network-distribution-graph', 'event-timestamps'],
]);
if (!$ajax
    && $this->Acl->canAccess('eventTemplates', 'index')
    && $this->Acl->canAccess('eventTemplates', 'instantiate')
) {
    echo $this->element('eventTemplates/templatePickerModal');
}
?>
