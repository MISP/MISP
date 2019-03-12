/*
*
*/

(function(factory) {
        "use strict";
        if (typeof define === 'function' && define.amd) {
            define(['jquery'], factory);
        } else if (window.jQuery && !window.jQuery.fn.DistributionNetwork) {
            factory(window.jQuery);
        }
    }
    (function($) {
        'use strict';

        // DistributionNetwork object
        var DistributionNetwork = function(container, options) {
            this._default_options = {
                network_options: {
                    width: '800px',
                    height: '759px',
                    layout: {randomSeed: 0},
                    edges: {
                        arrowStrikethrough: false,
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
                            gravitationalConstant: -10000,
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
                            color: '#ff9725',
                            shape: 'box',
                            margin: 3
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
                },
                EDGE_LENGTH_HUB: 300,
            };

            this.container = $(container);
            this._validateOptions(options);

            this.network_wrapper = false;
            this.options = $.extend({}, this._default_options, options);
            this.event_distribution = this.options.event_distribution;
            this.scope_id = this.options.scope_id;
            this.distributionData = this.options.distributionData;
            this.active = false;
            this.network;
            this.nodes_distri;
            this.edges_distri;
            this.cacheAddedOrgName = {};

            this._constructUI();
            this._registerListener();
        };

        DistributionNetwork.prototype = {
            constructor: DistributionNetwork,

            _validateOptions: function(options) {
                if (options.event_distribution === undefined) {
                    // try to fetch is from the container
                    var event_distribution = this.container.data('event-distribution');
                    if (event_distribution !== undefined) {
                        options.event_distribution = event_distribution;
                    } else {
                        throw "Event distribution not set";
                    }
                }
                if (options.distributionData === undefined) {
                    throw "Distribution data not set";
                }
                if (options.scope_id === undefined) {
                    // try to fetch is from the container
                    var scope_id = this.container.data('scope-id');
                    if (scope_id !== undefined) {
                        options.scope_id = scope_id;
                    } else {
                        throw "Scope id is not set";
                    }
                }
            },

            _registerListener: function() {
                var that = this;
                this.container.click(function() {
                    $('#sharingNetworkWrapper').toggle('slide', {direction: 'right'}, 300);
                    that._construct_network();
                });

            },

            dismissNetwork: function() {
                $('#sharingNetworkWrapper').hide('slide', {direction: 'right'}, 300);
            },

            _constructUI: function() {
                var that = this;
                if ($('#sharingNetworkWrapper').length > 0) {
                    return; // Wrapper already exists
                }
                var $div = $('<div id="sharingNetworkWrapper" class="advancedSharingNetwork hidden">'
                    + '<div class="eventgraph_header" style="border-radius: 5px; display: flex;">'
                    + '<it class="fa fa-circle-o" style="margin: auto 10px; font-size: x-large"></it>'
                    + '<input type="text" id="sharingNetworkTargetId" class="center-in-network-header network-typeahead" style="width: 200px;" disabled></input>'
                    + '<div class="form-group" style="margin: auto 10px;"><div class="checkbox">'
                        + '<label style="user-select: none;"><input id="interactive_picking_mode" type="checkbox" title="Click on a element to see how it is distributed" style="margin-top: 4px;">Enable interactive picking mode</label>'
                    + '</div></div>'
                    + '<select type="text" id="sharingNetworkOrgFinder" class="center-in-network-header network-typeahead sharingNetworkOrgFinder" style="width: 200px;"></select>'
                    + '<button id="closeButton" type="button" class="close" style="margin: 1px 5px; right: 0px; position: absolute;">×</button>'
                    + '</div><div id="advancedSharingNetwork"></div></div>');
                this.network_wrapper = $div;
                $div.find('#closeButton').click(function() {
                    that.dismissNetwork();
                });
                $('body').append($div);
            },

            _construct_network: function(target_distribution, scope_text, overwriteSg) {
                var that = this;
                if (this.network !== undefined) {
                    this.network.destroy();
                }
                if (scope_text == undefined) {
                    scope_text = 'Event ' + this.options.scope_id;
                }
                $('#sharingNetworkTargetId').val(scope_text);

                this.nodes_distri = new vis.DataSet([
                    {id: 'root', group: 'root', label: scope_text, x: 0, y: 0, fixed: true, mass: 20},
                    {id: this.distributionData.additionalDistributionInfo[0][0], label: this.distributionData.additionalDistributionInfo[0][0], group: 'org-only'},

                ]);
                this.edges_distri = new vis.DataSet([
                    {from: 'root', to: this.distributionData.additionalDistributionInfo[0][0], length: 30, width: 3},
                ]);
                if (target_distribution === undefined || target_distribution == 5) {
                    target_distribution = this.event_distribution;
                }

                console.log(this.distributionData);
                if (target_distribution !== 0) {
                    // Event always restrict propagation (sharing group is a special case)
                    var temp_target_disti = target_distribution;
                    if (target_distribution !== 4 && temp_target_disti >= this.event_distribution) {
                        while (temp_target_disti >= this.event_distribution) {
                            var toID = false;
                            switch (temp_target_disti) {
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
                            var edgeData = {from: 'root', to: toID, width: 3};
                            if (temp_target_disti != this.event_distribution) {
                                edgeData.label = 'X';
                                edgeData.title = 'The distribution of the Event restricts the distribution level of this element';
                                edgeData.font = {
                                    size: 50,
                                    color: '#ff0000',
                                    strokeWidth: 6,
                                    strokeColor: '#ff0000'
                                };
                            }
                            if (toID !== false) {
                                this.edges_distri.add(edgeData);
                            }
                            temp_target_disti--;
                        }
                    } else {
                        switch (temp_target_disti) {
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
                        var edgeData = {from: 'root', to: toID, width: 3};
                        if (toID !== false) {
                            this.edges_distri.add(edgeData);
                        }
                    }
                }

                var nodesToAdd = [];
                var edgesToAdd = [];
                this.cacheAddedOrgName[this.distributionData.additionalDistributionInfo[0][0]] = 1;

                // Community
                if (target_distribution >= 1 && target_distribution != 4
                    && (this.distributionData.event[1] > 0 || this.distributionData.event[2] > 0 || this.distributionData.event[3] > 0)
                ) {
                    nodesToAdd.push({id: 'this-community', label: 'This community', group: 'root-this-community'});
                    this._inject_this_community_org(nodesToAdd, edgesToAdd, this.distributionData.additionalDistributionInfo[1], 'this-community', 'this-community');
                }
                // Connected Community
                if (target_distribution >= 2 && target_distribution != 4
                    && (this.distributionData.event[2] > 0 || this.distributionData.event[3] > 0)
                ) {
                    nodesToAdd.push({id: 'connected-community', label: 'Connected community', group: 'root-connected-community'});
                    this.distributionData.additionalDistributionInfo[2].forEach(function(orgName) {
                        if (orgName === 'This community') {
                            edgesToAdd.push({from: 'connected-community', to: 'this-community', length: that.options.EDGE_LENGTH_HUB});
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
                if (target_distribution >= 3 && target_distribution != 4 && this.distributionData.event[3] > 0) {
                    nodesToAdd.push({id: 'all-community', label: 'All community', group: 'web'});
                    this.distributionData.additionalDistributionInfo[3].forEach(function(orgName) {
                        if (orgName === 'This community') {
                            edgesToAdd.push({from: 'all-community', to: 'this-community', length: that.options.EDGE_LENGTH_HUB});
                        } else if (orgName === 'All other communities') {
                            edgesToAdd.push({from: 'all-community', to: 'connected-community', length: that.options.EDGE_LENGTH_HUB});
                        }
                    });
                }
                // Sharing Group
                if (this.distributionData.event[4] > 0) {
                    this.distributionData.allSharingGroup.forEach(function(sg) {
                        var sgName = sg.SharingGroup.name;
                        if (overwriteSg === undefined) { // if overwriteSg not set, use the one from the event
                            overwriteSg = that.distributionData.additionalDistributionInfo[4];
                        }
                        if (overwriteSg.indexOf(sgName) == -1) {
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
                            if (that.cacheAddedOrgName[sgOrgName] === undefined) {
                                nodesToAdd.push({
                                    id: sgOrgName,
                                    label: sgOrgName,
                                    group: 'sharing-group'
                                });
                                that.cacheAddedOrgName[sgOrgName] = 1;
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
                Object.keys(this.cacheAddedOrgName).forEach(function(org) {
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
                        if (that.nodes_distri.get(this.value) !== null) {
                            that.network.focus(this.value, {animation: true});
                            that.network.selectNodes([this.value]);
                        }
                    } else {
                        that.network.fit({animation: true})
                    }
                });

                this.nodes_distri.add(nodesToAdd);
                this.edges_distri.add(edgesToAdd);
                var data = { nodes: this.nodes_distri, edges: this.edges_distri };
                this.network = new vis.Network(document.getElementById('advancedSharingNetwork'), data, this.options.network_options);

                this.network.on("dragStart", function (params) {
                    params.nodes.forEach(function(nodeId) {
                        that.nodes_distri.update({id: nodeId, fixed: {x: false, y: false}});
                    });
                });
                this.network.on("dragEnd", function (params) {
                    params.nodes.forEach(function(nodeId) {
                        that.nodes_distri.update({id: nodeId, fixed: {x: true, y: true}});
                    });
                });

                $('#interactive_picking_mode').off('change').on('change', function(e) {
                    var target_id = $(this).val();
                    if (this.checked) {
                        that._toggleRowListener(true);
                    } else {
                        that._toggleRowListener(false);
                        that._construct_network(this.event_distribution)
                    }
                });
            },

            _toggleRowListener: function(toAdd) {
                var that = this;
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
                                if (that.event_distribution == 4) {
                                    overwriteSg = that.event_distribution_text.trim();
                                }
                                break;
                            default:
                                distribution_value = 4;
                                overwriteSg = $dist_cell.text().trim();
                                break
                        }
                        that._construct_network(distribution_value, clicked_type+' '+clicked_id, [overwriteSg]);
                    });
                } else {
                    $('#attributes_div table tr').off('click.advancedSharing');
                }
            },

            _inject_this_community_org: function(nodesToAdd, edgesToAdd, orgs, group, root) {
                var that = this;
                orgs.forEach(function(orgName) {
                    if (that.cacheAddedOrgName[orgName] === undefined) {
                        nodesToAdd.push({
                            id: orgName,
                            label: orgName,
                            group: group
                        });
                        that.cacheAddedOrgName[orgName] = 1;
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
            },

        };

        $.distributionNetwork = DistributionNetwork;
        $.fn.distributionNetwork = function(option) {
            var pickedArgs = arguments;

            return this.each(function() {
                var $this = $(this),
                    inst = $this.data('distributionNetwork'),
                    options = ((typeof option === 'object') ? option : {});
                if ((!inst) && (typeof option !== 'string')) {
                    $this.data('distributionNetwork', new DistributionNetwork(this, options));
                } else {
                    if (typeof option === 'string') {
                        inst[option].apply(inst, Array.prototype.slice.call(pickerArgs, 1));
                    }
                }
            });
        };

        $.fn.distributionNetwork.constructor = DistributionNetwork;
    }));
