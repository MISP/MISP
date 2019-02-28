var scope_id = $('#eventdistri_graph').data('event-id');
var event_distribution = $('#eventdistri_graph').data('event-distribution');
var extended_text = $('#eventdistri_graph').data('extended') == 1 ? true : false;
var spanOffset_orig = 15; // due to padding
var payload = {};
var distribution_chart;
var distributionData;

var EDGE_LENGTH_HUB = 300;
var cacheAddedOrgName = {};
var nodes_distri;
var edges_distri;
var advancedSharingNetwork;

function clickHandlerGraph(evt) {
    var firstPoint = distribution_chart.getElementAtEvent(evt)[0];
    var distribution_id;
    if (firstPoint) {
        var value = distribution_chart.data.datasets[firstPoint._datasetIndex].data[firstPoint._index];
        if (value == 0) {
            document.getElementById('attributesFilterField').value = "";
            filterAttributes('all', scope_id);
        } else {
            distribution_id = distribution_chart.data.distribution[firstPoint._index].value;
            var value_to_set = String(distribution_id);
            value_to_set += distribution_id == event_distribution ? '|' + '5' : '';
            value_to_set = value_to_set.split('|');
            var rules = {
                condition: 'AND',
                rules: [
                    {
                        field: 'distribution',
                        value: value_to_set
                    }
                ]
            };
            performQuery(rules);
        }
    }
}

function generate_additional_info(info) {
    if (info.length == 0) {
        return "";
    } else {
        var to_ret = "\n\nInvolved:\n";
        var sel = document.createElement('select');
        sel.classList.add('distributionInfo');
        info.forEach(function(i) {
            var opt = document.createElement('option');
            opt.val = i;
            opt.innerHTML = i;
            sel.appendChild(opt);
        });
        return to_ret += sel.outerHTML;
    }
}

function clickHandlerPbText(evt) {
    var distribution_id = evt.target.dataset.distribution;
    var value_to_set = String(distribution_id);
    var rules = {
        condition: 'AND',
        rules: [
            {
                field: 'distribution',
                value: [value_to_set]
            }
        ]
    };
    performQuery(rules);
}
function clickHandlerPb(evt) {
    var distribution_id = $(evt.target).data('distribution');
    var value_to_set = String(distribution_id);
    value_to_set = value_to_set.split('|')
    var rules = {
        condition: 'AND',
        rules: [
            {
                field: 'distribution',
                value: value_to_set
            }
        ]
    };
    performQuery(rules);
}

function fill_distri_for_search(start_distri, end_distri) {
    var to_ret = "";
    for (var i=start_distri; i<end_distri; i++) {
        to_ret += String(i) + "|";
        to_ret += i==event_distribution ? "5|" : "";
    }
    to_ret += String(end_distri);
    to_ret += end_distri==event_distribution ? "|5" : "";
    return to_ret;
}

function get_maximum_distribution(array) {
    var org = array[0];
    var community = array[1];
    var connected = array[2];
    var all = array[3];
    var sharing = array[4];
    if (all != 0) {
        return 3;
    } else if (connected != 0) {
        return 2;
    } else if (community != 0) {
        return 1;
    } else {
        return 0;
    }
}

function get_minimum_distribution(array, event_dist) {
    var org = array[0];
    var community = array[1];
    var connected = array[2];
    var all = array[3];
    var sharing = array[4];
    if (connected != 0 && 3 == event_distribution) {
        return 2;
    } else if (community != 0 && 1 < event_distribution) {
        return 1;
    } else if (org != 0 && 0 < event_distribution) {
        return 0;
    } else {
        return -1;
    }
}

function add_level_to_pb(distribution, additionalInfo, maxLevel) {
    var pb_container = document.getElementById('eventdistri_pb_container');
    var pb = document.getElementById('eventdistri_pb_background');
    document.getElementById('eventdistri_graph').style.left = spanOffset_orig + 'px'; // center graph inside the popover
    var pbStep = pb.clientWidth / 4.0;
    var pb_top = pb.offsetTop;

    var spanOffset = spanOffset_orig;
    distribution = jQuery.extend({}, distribution); // deep clone distribution object
    for (var d in distribution) {
        d = parseInt(d);
        if (d == 4) { // skip sharing group
            continue;
        }
        // text
        var span = document.createElement('span');
        span.classList.add('useCursorPointer', 'pbDistributionText', 'badge');
        span.onclick = clickHandlerPbText;
        span.innerHTML = distribution[d].key;
        span.setAttribute('data-distribution', d);
        span.style.whiteSpace = 'pre-wrap';
        if (maxLevel == d+1) { // current event distribution
            span.style.fontSize = 'larger';
            span.style.top = d % 2 == 0 ? pb_top-37+'px' : pb_top+30+'px';
            span.style.boxShadow = '3px 3px 5px 1px rgba(0,0,0,0.6)';
        } else {
            span.style.opacity = '0.5';
            span.style.top = d % 2 == 0 ? pb_top-37+'px' : pb_top+30+'px';
        }
        pb_container.appendChild(span);
        if (d == Object.keys(distribution).length-2) { // last one, move a bit to the left. (-2 because sharing is not considered)
            span.style.left = (pbStep*(d+1))+spanOffset-span.clientWidth/2-35 + 'px';
        } else {
            span.style.left = (pbStep*(d+1))+spanOffset-span.clientWidth/2 + 'px';
        }
        var pop = $(span).popover({
            placement: d % 2 == 0 ? 'top' : 'bottom',
            trigger: 'click',
            content: '<b>Distribution description:</b> ' + distribution[d].desc + generate_additional_info(additionalInfo[d]),
            title: distribution[d].key,
            container: 'body',
            html: true,
            template: '<div class="popover" role="tooltip"><div class="arrow"></div><h3 class="popover-title distributionInfo"></h3><div class="popover-content distributionInfo" style="white-space: pre-wrap"></div></div>'
        });

        // tick
        var span = document.createElement('span');
        span.classList.add('pbDistributionTick');
        spanOffset += (pbStep*(d+1))+spanOffset > pb_container.clientWidth ? -3 : 0; // avoid the tick width to go further than the pb
        span.style.left = (pbStep*(d+1))+spanOffset + 'px';
        span.style.top = d % 2 == 0 ? pb_top-15+'px' : pb_top+0+'px';
        if (maxLevel == d+1) {
            span.style.opacity = '0.6';
        } else {
            span.style.opacity = '0.2';
        }
        pb_container.appendChild(span);
    }

}

function showAdvancedSharing(clicked) {
    $clicked = $(clicked);
    var network_active = $clicked.data('networkactive');
    if (network_active !== undefined && network_active === true) {
        $('#advancedSharingNetworkWrapper').hide('slide', {direction: 'right'}, 300);
        $clicked.data('networkactive', false);
        return;
    } else if (network_active !== undefined && network_active === false) {
        $('#advancedSharingNetworkWrapper').show('slide', {direction: 'right'}, 300);
        $clicked.data('networkactive', true);
        return;
    }
    $clicked.data('networkactive', true);
    var $popover = $('#eventdistri_graph').parent().parent();
    var boundingRect = $popover[0].getBoundingClientRect()
    var $div = $('<div id="advancedSharingNetworkWrapper" class="advancedSharingNetwork hidden">'
        + '<div class="eventgraph_header" style="border-radius: 5px; display: flex;">'
        + '<it class="fa fa-circle-o" style="margin: auto 10px; font-size: x-large"></it>'
        + '<input type="text" id="sharingNetworkTargetId" class="center-in-network-header network-typeahead" style="width: 200px;" disabled></input>'
        + '<div class="form-group" style="margin: auto 10px;"><div class="checkbox">'
            + '<label style="user-select: none;"><input id="interactive_picking_mode" type="checkbox" title="Click on a element to see how it is distributed" style="margin-top: 4px;">Enable interactive picking mode</label>'
        + '</div></div>'
        + '<select type="text" id="sharingNetworkOrgFinder" class="center-in-network-header network-typeahead sharingNetworkOrgFinder" style="width: 200px;"></select>'
        + '<button type="button" class="close" style="margin: 1px 5px; right: 0px; position: absolute;" onclick="$(\'#showAdvancedSharingButton\').click();">×</button>'
        + '</div><div id="advancedSharingNetwork"></div></div>');

    $('body').append($div);
    $div.toggle('slide', {direction: 'right'}, 300);

    construct_network();
}

function construct_network(target_distribution, scope_text, overwriteSg) {
    cacheAddedOrgName = {};
    if (advancedSharingNetwork !== undefined) {
        advancedSharingNetwork.destroy();
    }
    if (scope_text == undefined) {
        scope_text = 'Event ' + scope_id;
    }
    $('#sharingNetworkTargetId').val(scope_text);

    nodes_distri = new vis.DataSet([
        {id: 'root', group: 'root', label: scope_text, x: 0, y: 0, fixed: true},
        {id: distributionData.additionalDistributionInfo[0][0], label: distributionData.additionalDistributionInfo[0][0], group: 'org-only'},

    ]);
    edges_distri = new vis.DataSet([
        {from: 'root', to: distributionData.additionalDistributionInfo[0][0], length: 30, width: 3},
    ]);
    var toID = false;;
    if (target_distribution === undefined || target_distribution == 5) {
        target_distribution = event_distribution;
    }
    switch (target_distribution) {
        case 0:
            break;
        case 1:
            toID = 'this-community';
            break;
        case 2:
            toID = 'connected-community';
            break;
        case 3:
            toID = 'all-community';
            break;
        case 4:
            toID = 'sharing-group';
            break;
        default:
            break;
    }

    if (toID !== false) {
        var edgeData = {from: 'root', to: toID, width: 3};
        // Event always restrict propagation (sharing group is a special case)
        if (target_distribution !== 4 && target_distribution > event_distribution) {
            edgeData.label = 'X';
            edgeData.title = 'The distribution of the Event restricts the distribution level of this element';
            edgeData.font = {
                size: 50,
                color: '#ff0000',
                strokeWidth: 6,
                strokeColor: '#ff0000'
            };
        }
        edges_distri.add(edgeData);
    }

    var nodesToAdd = [];
    var edgesToAdd = [];
    cacheAddedOrgName[distributionData.additionalDistributionInfo[0][0]] = 1;

    // Community
    if (target_distribution >= 1 && target_distribution != 4) {
        nodesToAdd.push({id: 'this-community', label: 'This community', group: 'root-this-community'});
        inject_this_community_org(nodesToAdd, edgesToAdd, distributionData.additionalDistributionInfo[1], 'this-community', 'this-community');
    }
    if (target_distribution >= 2 && target_distribution != 4) {
        // Connected Community
        nodesToAdd.push({id: 'connected-community', label: 'Connected community', group: 'root-connected-community'});
        distributionData.additionalDistributionInfo[2].forEach(function(orgName) {
            if (orgName === 'This community') {
                edgesToAdd.push({from: 'connected-community', to: 'this-community', length: EDGE_LENGTH_HUB});
            } else {
                nodesToAdd.push({
                    id: 'connected-community_' + orgName,
                    label: orgName,
                    group: 'connected-community'
                });
                edgesToAdd.push({from: 'connected-community', to: 'connected-community_' + orgName});
            }
        });
    }

    // All Community
    if (target_distribution >= 3 && target_distribution != 4) {
        nodesToAdd.push({id: 'all-community', label: 'All community', group: 'web'});
        distributionData.additionalDistributionInfo[3].forEach(function(orgName) {
            if (orgName === 'This community') {
                edgesToAdd.push({from: 'all-community', to: 'this-community', length: EDGE_LENGTH_HUB});
            } else if (orgName === 'All other communities') {
                edgesToAdd.push({from: 'all-community', to: 'connected-community', length: EDGE_LENGTH_HUB});
            }
        });
    }
    // Sharing Group
    if (distributionData.event[4] > 0) {
        distributionData.allSharingGroup.forEach(function(sg) {
            var sgName = sg.SharingGroup.name;
            if (overwriteSg !== undefined && overwriteSg.indexOf(sgName) == -1) {
                return true;
            }

            nodesToAdd.push({
                id: 'sharing-group_' + sgName,
                label: sgName,
                group: 'root-sharing-group'
            });
            edgesToAdd.push({from: 'root', to: 'sharing-group_' + sgName, width: 3});
            sg.SharingGroupOrg.forEach(function(org) {
                var sgOrgName = org.Organisation.name;
                if (cacheAddedOrgName[sgOrgName] === undefined) {
                    nodesToAdd.push({
                        id: sgOrgName,
                        label: sgOrgName,
                        group: 'sharing-group'
                    });
                    cacheAddedOrgName[sgOrgName] = 1;
                }
                edgesToAdd.push({
                    from: 'sharing-group_' + sgName,
                    to: sgOrgName,
                    arrows: {
                        to: { enabled: false }
                    },
                    color: { opacity: 0.4 }
                });
            });
        });
    }

    var options = '<option></option>';
    $('#sharingNetworkOrgFinder').empty();
    Object.keys(cacheAddedOrgName).forEach(function(org) {
        options += '<option value="'+org+'">'+org+'</option>';
    });
    $('#sharingNetworkOrgFinder').append(options)
    .trigger('chosen:updated')
    .chosen({
        inherit_select_classes: true,
        no_results_text: "Focus to an organisation",
        placeholder_text_single: "Focus to an organisation",
        allow_single_deselect: true
    })
    .off('change')
    .on('change', function(evt, params) {
        if (this.value !== '') {
            advancedSharingNetwork.focus(this.value, {animation: true});
            advancedSharingNetwork.selectNodes([this.value]);
        } else {
            advancedSharingNetwork.fit({animation: true})
        }
    });

    nodes_distri.add(nodesToAdd);
    edges_distri.add(edgesToAdd);
    var data = { nodes: nodes_distri, edges: edges_distri };
    var network_options = {
        width: '800px',
        height: '800px',
        layout: {randomSeed: 0},
        edges: {
            arrows: {
                to: {enabled: true, scaleFactor:1, type:'arrow'},
            },
            shadow: {
                enabled: true,
                size: 7,
                x: 3,
                y: 3
            }
        },
        physics:{
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.3,
                springLength: 150,
                springConstant: 0.02,
                damping: 0.09,
                avoidOverlap: 0
            },
            repulsion: {
                centralGravity: 0.2,
                springLength: 200,
                springConstant: 0.02,
                nodeDistance: 200,
                damping: 0.15
            },

            solver: 'barnesHut'
        },
        nodes: {
            shadow: {
                enabled: true,
                size: 7,
                x: 3,
                y: 3
            }
        },
        groups: {
            'root': {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf10c',
                    color: '#000000',
                    size: 50
                },
                font: {size: 30},
                color: '#000000',
            },
            'org-only': {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf2c2',
                    color: '#ff0000',
                    size: 30
                },
                font: {
                    size: 14, // px
                    color: '#ff0000',
                    background: 'rgba(255, 255, 255, 0.7)'
                },
                color: '#ff0000',
            },
            'root-this-community': {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf1e1',
                    color: '#ff9725',
                    size: 70
                },
                font: {
                    size: 18, // px
                    color: '#ff9725',
                    background: 'rgba(255, 255, 255, 0.7)'
                },
                color: '#ff9725',
            },
            'this-community': {
                font: {color: 'white'},
                color: '#ff9725'
            },
            'root-connected-community': {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf0e8',
                    color: '#9b6e1b',
                    size: 70
                },
                font: {
                    size: 18, // px
                    color: '#9b6e1b',
                    background: 'rgba(255, 255, 255, 0.7)'
                },
                color: '#9b6e1b',
            },
            'connected-community': {
                shape: 'image',
                image: '/img/orgs/MISP.png'
            },
            'web': {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf0ac',
                    color: '#007d20',
                    size: 70
                },
                font: {
                    size: 18, // px
                    color: '#007d20',
                    background: 'rgba(255, 255, 255, 0.7)'
                },
                color: '#007d20',
            },
            'root-sharing-group': {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf0c0',
                    color: '#1369a0',
                    size: 70
                },
                font: {
                    size: 18, // px
                    color: '#1369a0',
                    background: 'rgba(255, 255, 255, 0.7)'
                },
                color: '#1369a0',
            }
        }
    };
    advancedSharingNetwork = new vis.Network(document.getElementById('advancedSharingNetwork'), data, network_options);

    advancedSharingNetwork.on("dragStart", function (params) {
        params.nodes.forEach(function(nodeId) {
            nodes_distri.update({id: nodeId, fixed: {x: false, y: false}});
        });
    });
    advancedSharingNetwork.on("dragEnd", function (params) {
        params.nodes.forEach(function(nodeId) {
            nodes_distri.update({id: nodeId, fixed: {x: true, y: true}});
        });
    });

    $('#interactive_picking_mode').off('change').on('change', function(e) {
        var target_id = $(this).val();
        if (this.checked) {
            toggleRowListener(true);
        } else {
            toggleRowListener(false);
            construct_network(event_distribution)
        }
    });
}

function toggleRowListener(toAdd) {
    if (toAdd) {
        $('#attributes_div table tr').off('click.advancedSharing').on('click.advancedSharing', function() {
            var $row = $(this);
            var clicked_type = $row.attr('id').split('_')[0];
            var clicked_id = $row.attr('id').split('_')[1];
            // var $dist_cell = $row.find('#'+clicked_type+'_'+clicked_id+'_distribution_solid');
            var $dist_cell = $row.find('div').filter(function() {
                return $(this).attr('id') !== undefined && $(this).attr('id').includes(clicked_id+'_distribution');
            });

            var distribution_value;
            var overwriteSg;
            switch ($dist_cell.text().trim()) {
                case 'Organisation':
                    distribution_value = 0;
                    break;
                case 'Community':
                    distribution_value = 1;
                    break;
                case 'Connected':
                    distribution_value = 2;
                    break;
                case 'All':
                    distribution_value = 3;
                    break;
                case 'Inherit':
                    distribution_value = 5;
                    break;
                default:
                    distribution_value = 4;
                    overwriteSg = $dist_cell.text().trim();
                    break
            }
            construct_network(distribution_value, clicked_type+' '+clicked_id, [overwriteSg]);
        });
    } else {
        $('#attributes_div table tr').off('click.advancedSharing');
    }
}


function inject_this_community_org(nodesToAdd, edgesToAdd, orgs, group, root) {
    orgs.forEach(function(orgName) {
        if (cacheAddedOrgName[orgName] === undefined) {
            nodesToAdd.push({
                id: orgName,
                label: orgName,
                group: group
            });
            cacheAddedOrgName[orgName] = 1;
        }
        edgesToAdd.push({
            from: root,
            to: orgName,
            arrows: {
                to: { enabled: false }
            },
            color: { opacity: 0.4 }
        });
    });
}

$(document).ready(function() {
    var rightBtn = '<span type="button" id="showAdvancedSharingButton" title="Toggle advanced sharing network viewer" class="fa fa-share-alt useCursorPointer" aria-hidden="true" style="float:right; margin-left: 5px;" onclick="showAdvancedSharing(this)"></span>';
    var pop = $('.distribution_graph').popover({
        title: "<b>Distribution graph</b> [atomic event]" + rightBtn,
        html: true,
        content: function() { return $('#distribution_graph_container').html(); },
        template : '<div class="popover" role="tooltip" style="z-index: 1;"><div class="arrow"></div><h3 class="popover-title"></h3><div class="popover-content" style="padding-left: '+spanOffset_orig+'px; padding-right: '+spanOffset_orig*2+'px;"></div></div>'
    });

    $('body').on('mouseup', function(e) {
        if(!$(e.target).hasClass('distributionInfo') && !($(e.target).hasClass('pbDistributionText') || $(e.target).hasClass('sharingGroup_pb_text'))) {
            $('.pbDistributionText').popover('hide');
            $('.sharingGroup_pb_text').popover('hide');
        }
    });

    $('.distribution_graph').click(function() {
        if ($(this).data('shown') == 'true') {
            $(this).data('shown', 'false');
            $('#advancedSharingNetworkWrapper').hide('slide', {direction: 'right'}, 200, function() { $('#advancedSharingNetworkWrapper').remove(); });
            return;
        } else {
            $(this).data('shown', 'true');
        }
        $.ajax({
            url: "/events/"+"getDistributionGraph"+"/"+scope_id+"/event.json",
            dataType: 'json',
            type: 'post',
            contentType: 'application/json',
            data: JSON.stringify( payload ),
            processData: false,
            beforeSend: function (XMLHttpRequest) {
                $(".loadingPopover").show();
            },
            success: function( data, textStatus, jQxhr ){
                distributionData = data;
                $(".loadingPopover").hide();

                // DISTRIBUTION PROGRESSBAR
                $('#eventdistri_pb_invalid').tooltip();
                $('#eventdistri_pb').tooltip();
                $('#eventdistri_pb_min').tooltip();

                $('#eventdistri_pb_invalid').click(function(evt) { clickHandlerPb(evt); });
                $('#eventdistri_pb').click(function(evt) { clickHandlerPb(evt); });
                $('#eventdistri_pb_min').click(function(evt) { clickHandlerPb(evt); });
                $('#eventdistri_sg_pb').click(function(evt) { clickHandlerPb(evt); });

                // pb
                var event_dist, min_distri, max_distri;
                if (event_distribution == 4) { // if distribution is sharing group, overwrite default behavior
                    var event_dist = 1;
                    var min_distri = 0;
                    var max_distri = 0;
                } else {
                    var event_dist = event_distribution+1; // +1 to reach the first level
                    var min_distri = get_minimum_distribution(data.event, event_dist)+1; // +1 to reach the first level
                    var max_distri = get_maximum_distribution(data.event)+1; // +1 to reach the first level
                }
                add_level_to_pb(data.distributionInfo, data.additionalDistributionInfo, event_dist);

                var bg_width_step = $('#eventdistri_pb_background').width()/4.0;
                $('#eventdistri_pb_min').width(bg_width_step*min_distri + 'px');
                $('#eventdistri_pb_min').data("distribution", fill_distri_for_search(0, min_distri-1));
                $('#eventdistri_pb_min').attr('aria-valuenow', min_distri*25);
                $('#eventdistri_pb_min').css("background", "#ffc107");

                $('#eventdistri_pb').width((event_dist)*25+'%');
                $('#eventdistri_pb').data("distribution", fill_distri_for_search(0, event_dist-1));
                $('#eventdistri_pb').attr('aria-valuenow', (event_dist-min_distri)*25);
                $('#eventdistri_pb').css("background", "#28a745");

                $('#eventdistri_pb_invalid').width((max_distri-event_dist)*25+'%');
                $('#eventdistri_pb_invalid').data("distribution", fill_distri_for_search(event_dist, max_distri-1));
                $('#eventdistri_pb_invalid').attr('aria-valuenow', (max_distri-event_dist)*25);
                $('#eventdistri_pb_invalid').css("background", "#dc3545");

                // SHARING GROUPS
                var sgNum = data.additionalDistributionInfo[4].length;
                var sgPerc = (sgNum/data.allSharingGroup.length)*100;
                if (sgPerc > 0) {
                    $('#eventdistri_sg_pb').width(sgPerc+'%');
                    $('#eventdistri_sg_pb').tooltip({
                        title: "Distribution among sharing group: "+(sgNum +' / '+ data.allSharingGroup.length)
                    });
                    $('#eventdistri_sg_pb').data("distribution", '4' + (event_distribution==4 ? '|5' : ''));
                    $('#eventdistri_sg_pb').attr('aria-valuenow', sgPerc);
                    $('#eventdistri_sg_pb').css("background", "#7a86e0");
                } else { // no sg, hide it and display
                    $('#eventdistri_sg_pb_background').text("Event not distributed to any sharing group");
                }

                $('.sharingGroup_pb_text').popover({
                    placement: 'bottom',
                    trigger: 'click',
                    title: 'Sharing group',
                    content: '<b>Distribution description:</b> ' + data.distributionInfo[4].desc + generate_additional_info(data.additionalDistributionInfo[4]),
                    container: 'body',
                    html: true,
                    template: '<div class="popover" role="tooltip"><div class="arrow"></div><h3 class="popover-title distributionInfo"></h3><div class="popover-content distributionInfo" style="white-space: pre-wrap"></div></div>'
                });

                // doughtnut
                var doughnutColors = ['#ff0000', '#ff9e00', '#957200', '#008000', 'rgb(122, 134, 224)'];
                var doughnut_dataset = [
                    {
                        label: "All",
                        data: data.event,
                        hidden: false,
                        backgroundColor: doughnutColors
                    },
                    {
                        label: "Attributes",
                        data: data.attribute,
                        hidden: false,
                        backgroundColor: doughnutColors
                    },
                    {
                        label: "Object attributes",
                        data: data.obj_attr,
                        hidden: false,
                        backgroundColor: doughnutColors
                    },

                ];
                var ctx = document.getElementById("distribution_graph_canvas");
                ctx.onclick = function(evt) { clickHandlerGraph(evt); };

                var count = 0;
                for (var i=0, n=data.event.length; i < n; i++) {
                  count += data.event[i];
                }
                if (count > 0) {
                    distribution_chart = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: data.distributionInfo.map(function(elem, index) { return [elem.key]; }),
                            distribution: data.distributionInfo,
                            datasets: doughnut_dataset,
                        },
                        options: {
                            title: {
                                display: false
                            },
                            animation: {
                                duration: 500
                            },
                            tooltips: {
                                callbacks: {
                                    label: function(item, data) {
                                        return data.datasets[item.datasetIndex].label
                                            + " - " + data.labels[item.index]
                                            + ": " + data.datasets[item.datasetIndex].data[item.index];
                                    }
                                }
                            }
                        },
                    });
                } else {
                    var canvas = ctx;
                    ctx = canvas.getContext("2d");
                    ctx.font = "30px Comic Sans MS";
                    ctx.textAlign = "center";
                    ctx.fillText("Event is empty", canvas.width/2, canvas.height/2);
                }

                // create checkboxes
                var div = $('<div></div>');
                div.addClass('distribution_checkboxes_dataset');
                var distri_graph = $('#eventdistri_graph');
                var distriOffset = distri_graph.offset();
                var distriHeight = distri_graph.height()/2;
                div.css({left: '50px'});
                for (var i in doughnut_dataset) {
                    var item = doughnut_dataset[i];
                    var label = $('<label></label>');
                    label.addClass('useCursorPointer');
                    label.css({'user-select': 'none'});
                    var checkbox = $('<input type="checkbox">');
                    checkbox.data('dataset-index', i);
                    checkbox.prop('checked', true);
                    checkbox.change(function(evt) {
                        var clickedIndex = $(this).data('dataset-index');
                        var isChecked = $(this).prop('checked');
                        distribution_chart.config.data.datasets[clickedIndex].hidden = !isChecked;
                        distribution_chart.update();
                    });
                    label.append(checkbox);
                    label.append(item.label);
                    div.append(label);
                }
                distri_graph.append(div);
            },
            error: function( jqXhr, textStatus, errorThrown ){
                console.log( errorThrown );
            }
        });
    });
});
