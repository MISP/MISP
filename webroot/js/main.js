function executePagination(selector, url) {
    UI.reload(url, $(selector), $(selector).find('table.table'))
}

function executeStateDependencyChecks(dependenceSourceSelector) {
    if (dependenceSourceSelector === undefined) {
        var tempSelector = "[data-dependence-source]";
    } else {
        var tempSelector = '*[data-dependence-source="' + dependenceSourceSelector + '"]';
    }
    $(tempSelector).each(function (index, dependent) {
        var dependenceSource = $(dependent).data('dependence-source');
        if ($(dependent).data('dependence-option') === $(dependenceSource).val()) {
            $(dependent).parent().parent().removeClass('d-none');
        } else {
            $(dependent).parent().parent().addClass('d-none');
        }
    });
}

function toggleAllAttributeCheckboxes(clicked) {
    let $clicked = $(clicked)
    let $table = $clicked.closest('table')
    let $inputs = $table.find('input.selectable_row')
    $inputs.prop('checked', $clicked.prop('checked'))
}

function testConnection(id) {
    $container = $(`#connection_test_${id}`)
    UI.overlayUntilResolve(
        $container[0],
        AJAXApi.quickFetchJSON(`/broods/testConnection/${id}`),
        { text: 'Running test' }
    ).then(result => {
        const $testResult = attachTestConnectionResultHtml(result, $container)
        $(`#connection_test_${id}`).append($testResult)
    })
        .catch((error) => {
            const $testResult = attachTestConnectionResultHtml(error.message, $container)
            $(`#connection_test_${id}`).append($testResult)
        })
}

function attachTestConnectionResultHtml(result, $container) {
    function getKVHtml(key, value, valueClasses = [], extraValue = '') {
        return $('<div/>').append(
            $('<strong/>').text(key + ': '),
            $('<span/>').addClass(valueClasses).text(value),
            $('<span/>').text(extraValue.length > 0 ? ` (${extraValue})` : '')
        )
    }
    $container.find('div.tester-result').remove()
    $testResultDiv = $('<div class="tester-result"></div>');
    if (typeof result !== 'object') {
        $testResultDiv.append(getKVHtml('Internal error', result, ['text-danger fw-bold']))
    } else {
        if (result['error']) {
            $testResultDiv.append(
                getKVHtml('Status', `Error: ${result['error']}`, ['text-danger'], (result['ping'] ? `${result['ping']} ms` : '')),
                getKVHtml('Reason', result['reason'], ['text-danger'])
            )
        } else {
            const canSync = result['response']['role']['perm_admin'] || result['response']['role']['perm_sync'];
            $testResultDiv.append(
                getKVHtml('Status', 'OK', ['text-success'], `${result['ping']} ms`),
                getKVHtml('Remote', `${result['response']['application']} v${result['response']['version']}`),
                getKVHtml('User', result['response']['user'], [], result['response']['role']['name']),
                getKVHtml('Sync permission', (canSync ? 'Yes' : 'No'), [(canSync ? 'text-success' : 'text-danger')]),
            )
        }
    }
    return $testResultDiv
}

function syntaxHighlightJson(json, indent) {
    if (indent === undefined) {
        indent = 2;
    }
    if (typeof json == 'string') {
        json = JSON.parse(json);
    }
    json = JSON.stringify(json, undefined, indent);
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/(?:\r\n|\r|\n)/g, '<br>').replace(/ /g, '&nbsp;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        var cls = 'text-info';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'text-primary';
            } else {
                cls = '';
            }
        } else if (/true|false/.test(match)) {
            cls = 'text-info';
        } else if (/null/.test(match)) {
            cls = 'text-danger';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

function getTextColour(hex) {
    if (hex === undefined || hex.length == 0) {
        return 'black'
    }
    hex = hex.slice(1)
    var r = parseInt(hex.substring(0, 2), 16)
    var g = parseInt(hex.substring(2, 4), 16)
    var b = parseInt(hex.substring(4, 6), 16)
    var avg = ((2 * r) + b + (3 * g)) / 6
    if (avg < 128) {
        return 'white'
    } else {
        return 'black'
    }
}

function performGlobalSearch(evt) {
    const $input = $('#globalSearch')
    const $resultContainer = $('.global-search-result-container')
    const value = $input.val()
    const leftKey = 37,
        upKey = 38,
        rightKey = 39,
        downKey = 40,
        ingoredKeys = [leftKey, upKey, rightKey, downKey]
    if (ingoredKeys.indexOf(evt.keyCode) != -1) {
        return;
    }
    if (value.length < 3 && evt.keyCode != 13) {
        bootstrap.Dropdown.getOrCreateInstance('#dropdownMenuSearchAll').hide()
        return;
    }
    const endpoint = '/instance/searchAll'
    const searchParams = new URLSearchParams({ search: value });
    const url = endpoint + '?' + searchParams
    const options = {
        statusNode: $resultContainer.find('.search-results-wrapper')
    }

    bootstrap.Dropdown.getOrCreateInstance('#dropdownMenuSearchAll').show()
    AJAXApi.quickFetchURL(url, options).then((theHTML) => {
        $resultContainer.html(theHTML)
    })
}

function focusSearchResults(evt) {
    const upKey = 38,
        downKey = 40
    if ([upKey, downKey].indexOf(evt.keyCode) != -1) {
        $('.global-search-result-container').find('.dropdown-item').first().focus()
    }
}

function saveSetting(statusNode, settingName, settingValue) {
    const url = window.saveSettingURL
    const data = {
        name: settingName,
        value: settingValue,
    }
    const APIOptions = {
        statusNode: statusNode,
    }
    return AJAXApi.quickFetchAndPostForm(url, data, APIOptions)
}

function openSaveBookmarkModal(bookmark_url = '') {
    const url = '/user-settings/saveMyBookmark';
    UI.submissionModal(url).then(([modalFactory, ajaxApi]) => {
        const $input = modalFactory.$modal.find('input[name="bookmark_url"]')
        $input.val(bookmark_url)
    })
}

function deleteBookmark(bookmark, forSidebar = false) {
    const url = '/user-settings/deleteMyBookmark'
    AJAXApi.quickFetchAndPostForm(url, {
        bookmark_name: bookmark.name,
        bookmark_url: bookmark.url,
    }, {
        provideFeedback: true,
        statusNode: $('.bookmark-table-container'),
    }).then((apiResult) => {
        const url = `/userSettings/getMyBookmarks/${forSidebar ? '1' : '0'}`
        UI.reload(url, $('.bookmark-table-container').parent())
        const theToast = UI.toast({
            variant: 'success',
            title: apiResult.message,
            bodyHtml: $('<div/>').append(
                $('<span/>').text('Cancel deletion operation.'),
                $('<button/>').addClass(['btn', 'btn-primary', 'btn-sm', 'ms-3']).text('Restore bookmark').click(function () {
                    const urlRestore = '/user-settings/saveMyBookmark'
                    AJAXApi.quickFetchAndPostForm(urlRestore, {
                        bookmark_label: bookmark.label,
                        bookmark_name: bookmark.name,
                        bookmark_url: bookmark.url,
                    }, {
                        provideFeedback: true,
                        statusNode: $('.bookmark-table-container')
                    }).then(() => {
                        const url = `/userSettings/getMyBookmarks/${forSidebar ? '1' : '0'}`
                        UI.reload(url, $('.bookmark-table-container').parent())
                    })
                }),
            ),
        })
    }).catch((e) => { })
}

function downloadIndexTable(downloadButton, filename) {
    const $dropdownMenu = $(downloadButton).closest('.dropdown')
    const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
    const $container = $dropdownMenu.closest('div[id^="table-container-"]')
    const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
    const $filterButton = $(`#toggleFilterButton-${tableRandomValue}`)
    const activeFilters = $filterButton.data('activeFilters')
    const additionalUrlParams = $filterButton.data('additionalUrlParams') ? $filterButton.data('additionalUrlParams') : ''
    const searchParam = jQuery.param(activeFilters);
    const url = $table.data('reload-url') + additionalUrlParams + '?' + searchParam
    let options = {}
    const downloadPromise = AJAXApi.quickFetchJSON(url, options)
    UI.overlayUntilResolve($dropdownMenu, downloadPromise)
    downloadPromise.then((data) => {
        download(filename, JSON.stringify(data, undefined, 4))
    })
}

function overloadBSDropdown() {
    // Inspired from https://jsfiddle.net/dallaslu/mvk4uhzL/
    (function ($bs) {
        const CLASS_NAME_HAS_CHILD = 'has-child-dropdown-show';
        const CLASS_NAME_KEEP_OPEN = 'keep-dropdown-show';

        $bs.Dropdown.prototype.toggle = function (_orginal) {
            return function () {
                document.querySelectorAll('.' + CLASS_NAME_HAS_CHILD).forEach(function (e) {
                    e.classList.remove(CLASS_NAME_HAS_CHILD);
                });
                let dd = this._element.closest('.dropdown')
                if (dd !== null) {
                    dd = dd.parentNode.closest('.dropdown');
                    for (; dd && dd !== document; dd = dd.parentNode.closest('.dropdown')) {
                        dd.classList.add(CLASS_NAME_HAS_CHILD);
                    }

                    if (this._element.classList.contains('open-form')) {
                        const openFormId = this._element.getAttribute('data-open-form-id')
                        document.querySelectorAll('.' + CLASS_NAME_KEEP_OPEN).forEach(function (e) {
                            e.classList.remove(CLASS_NAME_KEEP_OPEN);
                        });
                        let dd = this._element.closest('.dropdown')
                        dd.classList.add(CLASS_NAME_KEEP_OPEN);
                        dd.setAttribute('data-open-form-id', openFormId)
                        dd = dd.parentNode.closest('.dropdown');
                        for (; dd && dd !== document; dd = dd.parentNode.closest('.dropdown')) {
                            dd.setAttribute('data-open-form-id', openFormId)
                            dd.classList.add(CLASS_NAME_KEEP_OPEN);
                        }
                    }
                }
                return _orginal.call(this);
            }
        }($bs.Dropdown.prototype.toggle);
    })(bootstrap);
}

function addSupportOfNestedDropdown() {
    const CLASS_NAME_HAS_CHILD = 'has-child-dropdown-show';
    document.querySelectorAll('.dropdown').forEach(function (dd) {
        if (dd.getAttribute('data-listener-registered') === null) { // Only add listener once
            dd.addEventListener('hide.bs.dropdown', function (e) {
                if (this.classList.contains(CLASS_NAME_HAS_CHILD)) {
                    this.classList.remove(CLASS_NAME_HAS_CHILD);
                    e.preventDefault();
                }

                if (e.clickEvent !== undefined) {
                    let dd = e.clickEvent.target.closest('.dropdown')
                    if (dd !== null) {
                        if (dd.classList.contains('keep-dropdown-show')) {
                            e.preventDefault();
                        }
                    }
                }
                e.stopPropagation(); // do not need pop in multi level mode
            });
            dd.setAttribute('data-listener-registered', 1)
        }
    });
}

var UI
$(document).ready(() => {
    if (typeof UIFactory !== "undefined") {
        UI = new UIFactory()
    }
    overloadBSDropdown();
    addSupportOfNestedDropdown();

    if (window.debounce) {
        const debouncedGlobalSearch = debounce(performGlobalSearch, 400)
        $('#globalSearch')
            .keydown(debouncedGlobalSearch)
            .keydown(focusSearchResults);
    }

    $('.lock-sidebar a.btn-lock-sidebar').click(() => {
        const $sidebar = $('.sidebar')
        let expanded = $sidebar.hasClass('expanded');
        if (expanded) {
            $sidebar.removeClass('expanded')
        } else {
            $sidebar.addClass('expanded')
        }
        const settingName = 'ui.sidebar.expanded';
        const url = `/user-settings/setMySetting/${settingName}`
        AJAXApi.quickFetchAndPostForm(url, {
            value: expanded ? 0 : 1
        }, { provideFeedback: false })
    })

    $('.sidebar #btn-add-bookmark').click(() => {
        openSaveBookmarkModal(window.location.pathname)
    })
})

function simpleTabPage(page) {
    $(".progress_tab").removeClass("btn-primary").addClass("btn-inverse");
    $("#page" + page + "_tab").removeClass("btn-inverse").addClass("btn-primary");
    $(".tabContent").hide();
    $("#page" + page + "_content").show();
    if (page == lastPage) simpleTabPageLast();
}

function simpleTabPageLast() {
    var summaryorgs = summaryextendorgs = remotesummaryorgs = remotesummaryextendorgs = summaryservers = "";
    var orgcounter = extendcounter = remoteorgcounter = remoteextendcounter = servercounter = 0;
    var sgname = "[Sharing group name not set!]";
    if ($('#SharingGroupName').val()) sgname = $('#SharingGroupName').val();
    var sgreleasability = "[Sharing group releasability not set!]";
    if ($('#SharingGroupReleasability').val()) sgreleasability = $('#SharingGroupReleasability').val();
    $('#summarytitle').text(sgname);
    $('#summaryreleasable').text(sgreleasability);
    organisations.forEach(function (organisation) {
        if (organisation.type == 'local') {
            if (orgcounter > 0) summaryorgs += ", ";
            summaryorgs += organisation.name;
            if (organisation.extend == true) {
                if (extendcounter > 0) summaryextendorgs += ", "
                summaryextendorgs += organisation.name;
                extendcounter++;
            }
            orgcounter++;
        } else {
            if (remoteorgcounter > 0) remotesummaryorgs += ", ";
            remotesummaryorgs += organisation.name;
            if (organisation.extend == true) {
                if (remoteextendcounter > 0) remotesummaryextendorgs += ", "
                remotesummaryextendorgs += organisation.name;
                remoteextendcounter++;
            }
            remoteorgcounter++;
        }
    });
    if (orgcounter == 0) $('#localText').hide();
    if (remoteorgcounter == 0) $('#externalText').hide();
    if (extendcounter == 0) summaryextendorgs = "nobody";
    if (remoteextendcounter == 0) remotesummaryextendorgs = "nobody";
    servers.forEach(function (server) {
        if (servercounter > 0) summaryservers += ", ";
        if (server.id != 0) {
            summaryservers += server.name;
            if (extendcounter == 0) summaryextendorgs = "none";
            servercounter++;
        }
        if (server.id == 0 && server.all_orgs == true) summaryorgs = "all organisations on this instance";
    });
    if ($('#SharingGroupRoaming').is(":checked")) {
        summaryservers = "any interconnected instances linked by an eligible organisation.";
    } else {
        if (servercounter == 0) {
            summaryservers = "data marked with this sharing group will not be pushed.";
        }
    }
    $('#summarylocal').text(summaryorgs);
    $('#summarylocalextend').text(summaryextendorgs);
    $('#summaryexternal').text(remotesummaryorgs);
    $('#summaryexternalextend').text(remotesummaryextendorgs);
    $('#summaryservers').text(summaryservers);
}

function sharingGroupPopulateOrganisations() {
    $('input[id=SharingGroupOrganisations]').val(JSON.stringify(organisations));
    $('.orgRow').remove();
    var id = 0;
    var html = '';
    organisations.forEach(function (org) {
        html = '<tr id="orgRow' + id + '" class="orgRow">';
        html += '<td class="short">' + org.type + '&nbsp;</td>';
        html += '<td>' + $('<div>').text(org.name).html() + '&nbsp;</td>';
        html += '<td>' + org.uuid + '&nbsp;</td>';
        html += '<td class="short" style="text-align:center;">';
        if (org.removable == 1) {
            html += '<input id="orgExtend' + id + '" type="checkbox" onClick="sharingGroupExtendOrg(' + id + ')" ';
            if (org.extend) html += 'checked';
            html += '>';
        } else {
            html += '<span class="icon-ok"></span>'
        }
        html += '</td>';
        html += '<td class="actions short">';
        if (org.removable == 1) html += '<span class="icon-trash" onClick="sharingGroupRemoveOrganisation(' + id + ')"></span>';
        html += '&nbsp;</td></tr>';
        $('#organisations_table tr:last').after(html);
        id++;
    });
}

function sharingGroupPopulateServers() {
    $('input[id=SharingGroupServers]').val(JSON.stringify(servers));
    $('.serverRow').remove();
    var id = 0;
    var html = '';
    servers.forEach(function (server) {
        html = '<tr id="serverRow' + id + '" class="serverRow">';
        html += '<td>' + server.name + '&nbsp;</td>';
        html += '<td>' + server.url + '&nbsp;</td>';
        html += '<td>';
        html += '<input id="serverAddOrgs' + id + '" type="checkbox" onClick="sharingGroupServerAddOrgs(' + id + ')" ';
        if (server.all_orgs) html += 'checked';
        html += '>';
        html += '</td>';
        html += '<td class="actions short">';
        if (server.removable == 1) html += '<span class="icon-trash" onClick="sharingGroupRemoveServer(' + id + ')"></span>';
        html += '&nbsp;</td></tr>';
        $('#servers_table tr:last').after(html);
        id++;
    });
}

function sharingGroupExtendOrg(id) {
    organisations[id].extend = $('#orgExtend' + id).is(":checked");
}

function sharingGroupServerAddOrgs(id) {
    servers[id].all_orgs = $('#serverAddOrgs' + id).is(":checked");
}

function sharingGroupPopulateUsers() {
    $('input[id=SharingGroupServers]').val(JSON.stringify(organisations));
}

function sharingGroupAdd(context, type) {
    if (context == 'organisation') {
        var jsonids = JSON.stringify(orgids);
        url = baseurl + '/organisations/fetchOrgsForSG/' + jsonids + '/' + type
    } else if (context == 'server') {
        var jsonids = JSON.stringify(serverids);
        url = baseurl + '/servers/fetchServersForSG/' + jsonids
    }
    $("#gray_out").fadeIn();
    simplePopup(url);
}

function sharingGroupRemoveOrganisation(id) {
    organisations.splice(id, 1);
    orgids.splice(id, 1);
    sharingGroupPopulateOrganisations();
}

function sharingGroupRemoveServer(id) {
    servers.splice(id, 1);
    serverids.splice(id, 1);
    sharingGroupPopulateServers();
}

function submitPicklistValues(context, local) {
    if (context == 'org') {
        var localType = 'local';
        if (local == 0) localType = 'remote';
        $("#rightValues  option").each(function() {
            if (orgids.indexOf($(this).val()) == -1) {
                organisations.push({
                        id: $(this).val(),
                        type: localType,
                        name: $(this).text(),
                        extend: false,
                        uuid: '',
                        removable: 1
                });
            }
            orgids.push($(this).val());
            sharingGroupPopulateOrganisations();
        });
    } else if (context == 'server') {
        $("#rightValues  option").each(function() {
            if (serverids.indexOf($(this).val()) == -1) {
                servers.push({
                        id: $(this).val(),
                        name: $(this).text(),
                        url: $(this).attr("data-url"),
                        all_orgs: false,
                        removable: 1
                });
            }
            serverids.push($(this).val());
            sharingGroupPopulateServers();
        });
    }
    $("#gray_out").fadeOut();
    $("#popover_form").fadeOut();
}

function cancelPicklistValues() {
    $("#popover_form").fadeOut();
    $("#gray_out").fadeOut();
}

function sgSubmitForm(action) {
    var ajax = {
        'organisations': organisations,
        'servers': servers,
        'sharingGroup': {
            'uuid': $('#SharingGroupUuid').val(),
            'name': $('#SharingGroupName').val(),
            'releasability': $('#SharingGroupReleasability').val(),
            'description': $('#SharingGroupDescription').val(),
            'active': $('#SharingGroupActive').is(":checked"),
            'roaming': $('#SharingGroupRoaming').is(":checked"),
        }
    };
    $('#SharingGroupJson').val(JSON.stringify(ajax));
    var formName = "#SharingGroup" + action + "Form";
    $(formName).submit();
}