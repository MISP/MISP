var TICK_NUM = 300;
$('#input_Tau').data('multiplier', $('#input_Tau').val()/TICK_NUM);

function multiplier() {
    return $('#input_Tau').data('multiplier');
}

function daysToText(days) {
    // hours = parseInt(hours);
    // var days = parseInt(hours / multiplier());
    // var rem_hours = parseInt(hours % multiplier());
    days = parseFloat(days);
    hours = parseInt((days - parseInt(days)) * 24);
    var text = ""
        + parseInt(days)
        + (days>1 ? " days" : " day");
    if (hours > 0) {
        text += " and " + hours + (hours>1 ? " hours" : " hour");
    }
    return text;
}

function toggleCB(clicked, force) {
    $clicked = $(clicked);
    var cb = $clicked.first().find('input');
    if (force === undefined) {
        cb.prop('checked', !cb.is(':checked'));
    } else {
        cb.prop('checked', force);
    }
}

function getValueYFromCanvas(canvas_height, curr_y) {
    return 100 * (canvas_height - curr_y) / canvas_height;
}

// returns the score with x in days
function getScore(x, base_score) {
    if (base_score === undefined) {
        base_score = 100;
    }
    var delta = parseFloat($('#input_Delta').val());
    var tau = parseInt($('#input_Tau').val());
    return parseFloat((base_score * (1 - Math.pow(x / tau, 1/delta))).toFixed(2));
}

function getBaseLog(x, y) {
  return parseFloat(Math.log(y) / Math.log(x));
}

function getDeltaFromPoint(x, y, base_score) {
    if (base_score === undefined) {
        base_score = 100.0;
    }
    // x = Math.min(parseFloat($('#input_Tau').val()), parseFloat(x)) * multiplier();
    // y = Math.min(100.0, parseFloat(y));
    // x = parseFloat(x) * multiplier();
    x = parseFloat(x);
    y = parseFloat(y);
    // var tau = parseFloat($('#input_Tau').val() * multiplier());
    var tau = parseFloat($('#input_Tau').val());
    var delta = 1 / getBaseLog(x / tau, 1 - (y / base_score));
    return parseFloat(delta);
}

function getReverseScore(y, base_score) {
    if (base_score === undefined) {
        base_score = 100;
    }
    var delta = parseFloat($('#input_Delta').val());
    var tau = parseInt($('#input_Tau').val());
    return (tau * Math.pow(1 - (y / base_score), delta)).toFixed(2);
}

function genDecay() {
    var threshold = parseInt($('#input_Threshold').val());
    return genAxis().map(function(e, x) {
        var y = getScore(x * multiplier());
        return y >= threshold ? y : 0;
    });
}

function genLine() {
    return genAxis().map(function(e) {
        return parseInt($('#input_Threshold').val());
    });
}

function genAxis(textLabel) {
    var tau = parseInt($('#input_Tau').val());
    return d3.range(0, tau + tau / TICK_NUM, tau / TICK_NUM);
}

function refreshGraph(updated) {
    if ($(updated).attr('id') == 'input_Tau') {
        $(updated).data('multiplier', $(updated).val()/TICK_NUM);
    }
    updateData();
    var threshold = parseInt($('#input_Threshold').val());
    refreshInfoCells(threshold);
}

function refreshInfoCells(threshold) {
    if (threshold === undefined) {
        threshold = parseInt($('#input_Threshold').val());
    }
    $('#infoCellHalved').text(daysToText(getReverseScore((100-threshold)/2 + threshold)));
    $('#infoCellExpired').text(daysToText(getReverseScore(threshold)));
    highlightMatchingRow();
}

function loadModel(clicked) {
    var $clicked = $(clicked);
    var tr = $clicked.closest('tr');
    parameters = {
        tau: parseFloat(tr.find('td.DMParameterTau')[0].innerHTML),
        delta: parseFloat(tr.find('td.DMParameterDelta')[0].innerHTML),
        threshold: parseInt(tr.find('td.DMParameterThreshold')[0].innerHTML)
    };
    var name = tr.find('td.DMName')[0].innerHTML;
    var desc = tr.find('td.DMDescription')[0].innerHTML;

    $('#input_Tau').val(parameters.tau);
    $('#input_Delta').val(parameters.delta);
    $('#input_Threshold').val(parameters.threshold);
    var $form = $('#saveForm');
    $form.find('[name="name"]').val(name);
    $form.find('[name="description"]').val(desc);
    chart.data.labels = genAxis();
    chart.data.datasets[0].data = genDecay();
    chart.data.datasets[1].data = genLine();
    refreshInfoCells(parameters.threshold);
    chart.update();
}

function retreiveData() {
    var data = {};
    var $form = $('#saveForm')
    data.name = $form.find('[name="name"]').val();
    data.description = $form.find('[name="description"]').val();
    var params = {};
    params.tau = parseInt($('#input_Tau').val());
    params.delta = parseFloat($('#input_Delta').val());
    params.threshold = parseInt($('#input_Threshold').val());
    data.parameters = params;
    return data;
}

function saveModel(clicked) {
    var $clicked = $(clicked);
    var type = $clicked.data('save-type');
    var model_id = false;
    var data = retreiveData();
    data.parameters = JSON.stringify(data.parameters);
    if (type == 'edit') {
        model_id = $clicked.data('model-id');
        if (!confirm('Confirm overwrite?')) {
            return;
        }
    }
    fetchFormAndSubmit($clicked, type, model_id, data);
}

function injectData($form, data) {
    Object.keys(data).forEach(function(k) {
        var v = data[k];
        var field = k.charAt(0).toUpperCase() + k.slice(1);
        $('#DecayingModel'+field).val(v);
    });
}

function highlightMatchingRow() {
    var data = retreiveData();
    delete data['name'];
    delete data['description'];
    var $rows = $('#modelTableBody').find('tr');
    $rows.removeClass('success');
    $rows.each(function(i) {
        var rowData = getDataFromRow($(this));
        delete rowData['name'];
        delete rowData['description'];
        if (simpleCompareObject(data, rowData)) {
            $(this).addClass('success');
        }
    });
}

function getDataFromRow($row) {
    var data = {};
    data.name = $row.find('td.DMName').text();
    data.description = $row.find('td.DMDescription').text();
    data.parameters = {};
    data.parameters.tau = parseInt($row.find('td.DMParameterTau').text());
    data.parameters.delta = parseFloat($row.find('td.DMParameterDelta').text());
    data.parameters.threshold = parseInt($row.find('td.DMParameterThreshold').text());
    return data;
}

function refreshRow(data) {
    var decayingModel = data.data.DecayingModel;
    var row = '<tr id="modelId_' + decayingModel.id + '">'
        + '<td class="DMName">' + decayingModel.name + '</td>'
        + '<td class="DMDescription">' + decayingModel.description + '</td>'
        + '<td class="DMParameterTau">' + decayingModel.parameters.tau + '</td>'
        + '<td class="DMParameterDelta">' + decayingModel.parameters.delta + '</td>'
        + '<td class="DMParameterThreshold">' + decayingModel.parameters.threshold + '</td>'
        + '<td data->'
        + '<button class="btn btn-primary btn-small" onclick="loadModel(this);"><span class="fa fa-arrow-up"> Load model</span></button>'
        + '<button class="btn btn-danger btn-small" style="margin-left: 3px;" data-save-type="edit" data-model-id="' + decayingModel.id + '" onclick="saveModel(this);"><span class="fa fa-paste"> Overwrite model</span></button>'
        + '</td>'
        + '</tr>';

    if (data.action == 'add') {
        var $row = $(row);
        $('#modelTableBody').append($row);
    } else {
        var $row = $('#modelId_'+decayingModel.id);
        $row[0].outerHTML = row;
    }
    highlightMatchingRow();
}

function simpleCompareObject(obj1, obj2) {
    var flag_same = true;
    var objectKeys = Object.keys(obj1);
    for (var i = 0; i < objectKeys.length; i++) {
        var k = objectKeys[i];
        var v1 = obj1[k];
        var v2 = obj2[k];

        if (v1 instanceof Object && v2 instanceof Object) {
            flag_same = simpleCompareObject(v1, v2);
        } else if ( (v1 instanceof Object) && !(v2 instanceof Object) || (!(v1 instanceof Object) && (v2 instanceof Object))) {
            return false;
        } else if (v1 !== v2) {
            return false;
        }

        if (!flag_same) {
            return false;
        }
    }
    return flag_same;
}

function fetchFormAndSubmit($clicked, type, model_id, formData) {
    var url = "/decayingModel/";
    if (type == "add") {
        url += type;
    } else {
        url += type + "/" + model_id;
    }
    var loadingSpan = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';

    $.get(url, function(data) {
        var $confbox = $("#confirmation_box");
        $confbox.html(data);
        var $form = $confbox.find('form');
        injectData($form, formData);
        $.ajax({
            data: $form.serialize(),
            cache: false,
            beforeSend: function(XMLHttpRequest) {
                $clicked.append(loadingSpan);
            },
            success: function(data, textStatus) {
                showMessage('success', 'Network has been saved');
                refreshRow(data);
            },
            error: function( jqXhr, textStatus, errorThrown ){
                showMessage('fail', 'Could not save network');
                console.log( errorThrown );
            },
            complete: function() {
                $clicked.find('#loadingSpan').remove();
                $form.remove();
            },
            type: 'post',
            url: url
        });
    });
}

function applyModel(clicked) {
    var $row = $(clicked).parent().parent();
    var rowData = getDataFromRow($row);
}

function updateData(computeFromHandle) {
    // update parameters based on the handle
    if (computeFromHandle !== undefined && computeFromHandle == 'decayingGraphHandleDot') {
        var handle = svg.select('.decayingGraphHandleDot');
        // var hx = parseInt(handle.attr('cx')) * multiplier();
        var hx = x.invert(handle.attr('cx'));
        var hy = getValueYFromCanvas(height, parseInt(handle.attr('cy')));
        var delta = getDeltaFromPoint(hx, hy);
        $('#input_Delta').val(delta);
    } else if (computeFromHandle !== undefined && computeFromHandle == 'decayingGraphDot') {
        var handle = svg.select('.decayingGraphDot');
        var hx = parseInt(handle.attr('cx'));
        var hy = parseInt(getValueYFromCanvas(height, parseInt(handle.attr('cy'))));
        $('#input_Threshold').val(hy);
    }

    var decay = genDecay();
    var axe = genAxis();
    var thres = genLine();
    var data = [];
    for (var i=0; i<decay.length; i++) {
        data.push({x: axe[i], y: decay[i], yThres: thres[i]});
    }

    // scale the range of the data
    x.domain(d3.extent(data, function(d) { return d.x; }));
    y.domain([0, d3.max(data, function(d) { return d.y; })]);

    svg.select(".decayingGraphLine")
        .data([data])
        .attr("d", valueline);
    svg.select(".decayingGraphLineThres")
        .data([data])
        .attr("d", valuelineThres);

    svg.select(".decayingGraphAreaThres")
        .data([data])
        .attr("d", areaThres);

    svg.select('.decayingGraphDot')
        .data([data])
        .attr("cx", function(d) { return x(getReverseScore(parseInt($('#input_Threshold').val()))); })
        .attr("cy", function(d, i) { return y(parseInt($('#input_Threshold').val())); });

    if (computeFromHandle === undefined) {
        svg.select('.decayingGraphHandleDot')
            .attr("cx", function(d) { return x(parseFloat($('#input_Tau').val()/2)); })
            .attr("cy", function(d) { return y(getScore(parseInt($('#input_Tau').val()/2))); });
    }

    svg.select(".axis-x")
        .call(xAxis);
}


var chart;
var data = [];
var svg, valueline, valuelineThres, area, areaThres, xAxis;
var x, y;
var height, width;
$(document).ready(function() {
    $('[data-toggle="tooltip"]').tooltip();
    var container = '#decayGraph';
    var $container = $(container);
    var margin = {top: 10, right: 10, bottom: 20, left: 30};
    width = $container.width() - margin.left - margin.right;
    height = 380 - margin.top - margin.bottom;
    x = d3.scale.linear().range([0, width]);
    y = d3.scale.linear().range([height, 0]);
    xAxis = d3.svg.axis().scale(x).orient('bottom');
    var yAxis = d3.svg.axis().scale(y).orient("left");

    var drag = d3.behavior.drag()
        .on("drag", dragmove);

    // define the area
    area = d3.svg.area()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y0(height)
        .y1(function(d) { return y(d.y); });
    areaThres = d3.svg.area()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y0(height)
        .y1(function(d) { return y(d.yThres); });

    // define the line
    valueline = d3.svg.line()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y(function(d) { return y(d.y); });
    valuelineThres = d3.svg.line()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y(function(d) { return y(d.yThres); });

    svg = d3.select(container)
        .append("svg")
            .attr("width", width + margin.left + margin.right)
            .attr("height", height + margin.top + margin.bottom)
        .append("g")
            .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var decay = genDecay();
    var axe = genAxis();
    var thres = genLine();
    for (var i=0; i<decay.length; i++) {
        data.push({x: axe[i], y: decay[i], yThres: thres[i]});
    }

    // scale the range of the data
    x.domain(d3.extent(data, function(d) { return d.x; }));
    y.domain([0, d3.max(data, function(d) { return d.y; })]);

    // add the valueline path.
    svg.append("path")
        .data([data])
        .attr("class", "decayingGraphLine")
        .attr("d", valueline);
    svg.append("path")
        .data([data])
        .attr("class", "decayingGraphLineThres")
        .attr("d", valuelineThres);

    svg.append("path")
    .data([data])
    .attr("class", "decayingGraphAreaThres")
    .attr("d", areaThres);

    svg.selectAll('.decayingGraphDot')
        .data([data])
        .enter()
        .append('g')
        .append('circle')
        .attr('id', 'decayingGraphDot')
        .attr('class', 'decayingGraphDot')
        .attr("cx", function(d) { return x(getReverseScore(parseInt($('#input_Threshold').val()))); })
        .attr("cy", function(d, i) { return y(parseInt($('#input_Threshold').val())); })
        .attr("r", 5)
        .call(drag);

    svg.selectAll('.decayingGraphHandleDot')
        .data([data])
        .enter()
        .append('g')
        .append('circle')
        .attr('id', 'decayingGraphHandleDot')
        .attr('class', 'decayingGraphHandleDot')
        .attr("cx", function(d) { return x(parseFloat($('#input_Tau').val()/2)); })
        .attr("cy", function(d) { return y(getScore(parseInt($('#input_Tau').val()/2))); })
        .attr("r", 5)
        .call(drag);
        // .on("mouseover", function(datum, b, c) {
        //
        // })
        // .on("mouseout", function() {  })

    // add the X Axis
    svg.append("g")
        .attr("class", "decayingGraphAxis axis-x")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis);

    // add the Y Axis
    svg.append("g")
        .attr("class", "decayingGraphAxis axis-y")
        .call(yAxis);


    function dragmove(d) {
        var point = d3.select(this);
        var id = point.attr('id');
        point.attr("cx", function() { return Math.max(Math.min(d3.event.x, width), 0); })
            .attr("cy", function() { return Math.max(Math.min(d3.event.y, height), 0); });
        updateData(id);
    }

    refreshInfoCells();
    $("#attributeTypeTableBody").selectable({
        filter: "tr:not(.hidden)",
        selected: function( event, ui ) {
            if (event.ctrlKey) {
                $(ui.selected).toggleClass("info");
                toggleCB($(ui.selected));
            } else {
                $(ui.selected).addClass("info");
                toggleCB($(ui.selected), true);
            }
        },
        unselected: function( event, ui ) {
            $(ui.unselected).removeClass("info");
            toggleCB($(ui.unselected), false);
        }
    });

    $('#attributeTypeTableBody').find('input[type="checkbox"]').change(function() {
        $row = $(this).closest('tr');
        $row.toggleClass('info', this.checked);
    });

    $('#checkAll').change(function() {
        var $checkboxes = $('#attributeTypeTableBody').find('input[type="checkbox"]');
        $checkboxes.prop('checked', this.checked);
        $row = $($checkboxes).closest('tr');
        $row.toggleClass('info', this.checked);
    });

    $('#table_toggle_all_type').change(function() {
        $('#attributeTypeTableBody').find('tr.isNotToIDS').toggleClass('hidden', !this.checked);
    });

    $('#table_toggle_objects').change(function() {
        $('#attributeTypeTableBody').find('tr.isObject').toggleClass('hidden', !this.checked);
    });
});
