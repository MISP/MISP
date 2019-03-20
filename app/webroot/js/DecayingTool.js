function hoursToText(hours) {
    hours = parseInt(hours);
    var days = parseInt(hours / 24);
    var rem_hours = parseInt(hours % 24);
    var text = ""
        + days
        + (days>1 ? " days" : " day");
    if (rem_hours > 0) {
        text += " and " + rem_hours + (rem_hours>1 ? " hours" : " hour");
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

function getScore(x, base_score) {
    if (base_score === undefined) {
        base_score = 100;
    }
    var delta = parseFloat($('#input_Delta').val());
    var tau = parseInt($('#input_Tau').val() * 24);
    return parseFloat((base_score * (1 - Math.pow(x / tau, 1/delta))).toFixed(2));
}

function getReverseScore(y, base_score) {
    if (base_score === undefined) {
        base_score = 100;
    }
    var delta = parseFloat($('#input_Delta').val());
    var tau = parseInt($('#input_Tau').val() * 24);
    return (tau * Math.pow(1 - (y / base_score), delta)).toFixed(2);
}

function genDecay() {
    var threshold = parseInt($('#input_Threshold').val());
    return genAxis().map(function(e, x) {
        var y = getScore(x);
        return y >= threshold ? y : 0;
    });
}

function genLine() {
    return genAxis().map(function(e) {
        return parseInt($('#input_Threshold').val());
    });
}

function genAxis(textLabel) {
    var tau = parseInt($('#input_Tau').val() * 24);

    var data = [];
    for (var i=0; i<(tau+1); i++) {
        data.push(i);
    }

    return data;
}

function refreshGraph(updated) {
    // var $this = $(updated);
    // var id = $this.attr('id');
    // var val = parseInt($this.val());
    // var threshold = parseInt($('#input_Threshold').val());
    // var datasetDecay = chart.data.datasets[0];
    // var updateOption = {};
    // switch(id) {
    //     case 'input_Threshold':
    //         for(var i=0; i<chart.data.datasets[1].data.length; i++) {
    //             chart.data.datasets[1].data[i] = threshold;
    //         }
    //         chart.data.datasets[0].data = genDecay();
    //         break;
    //     case 'input_Tau':
    //         chart.data.labels = genAxis();
    //         chart.data.datasets[0].data = genDecay();
    //         chart.data.datasets[1].data = genLine();
    //         updateOption['duration'] = 0;
    //         break;
    //     case 'input_Delta':
    //         chart.data.datasets[0].data = genDecay();
    //         break;
    //     default:
    //         break;
    // }
    // $('#'+id+'_range').val($this.val());
    //
    // refreshInfoCells(threshold);
    // chart.update(updateOption);
}

function refreshInfoCells(threshold) {
    if (threshold === undefined) {
        threshold = parseInt($('#input_Threshold').val());
    }
    $('#infoCellHalved').text(hoursToText(getReverseScore((100-threshold)/2 + threshold)));
    $('#infoCellExpired').text(hoursToText(getReverseScore(threshold)));
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

var chart;
var data = [];
$(document).ready(function() {
    $('[data-toggle="tooltip"]').tooltip();
    var container = '#decayGraph';
    var $container = $(container);
    var margin = {top: 10, right: 10, bottom: 20, left: 30};
    var width = $container.width() - margin.left - margin.right;
    var height = 380 - margin.top - margin.bottom;
    var x = d3.scale.linear().range([0, width]);
    var y = d3.scale.linear().range([height, 0]);
    var xAxis = d3.svg.axis().scale(x).orient('bottom');
    var yAxis = d3.svg.axis().scale(y).orient("left");

    var drag = d3.behavior.drag()
        .on("drag", dragmove);

    // define the area
    var area = d3.svg.area()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y0(height)
        .y1(function(d) { return y(d.y); });
    var areaThres = d3.svg.area()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y0(height)
        .y1(function(d) { return y(d.yThres); });

    // define the line
    var valueline = d3.svg.line()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y(function(d) { return y(d.y); });
    var valuelineThres = d3.svg.line()
        .interpolate("monotone")
        .x(function(d) { return x(d.x); })
        .y(function(d) { return y(d.yThres); });

    var svg = d3.select(container)
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
        .attr('class', 'yolo')
        .append('circle')
        .attr('class', 'decayingGraphDot')
        .attr("cx", function(d) { return x(getReverseScore(parseInt($('#input_Threshold').val()))); })
        .attr("cy", function(d, i) { return y(parseInt($('#input_Threshold').val())); })
        .attr("r", 5)
        .call(drag);
        // .on("mouseover", function(datum, b, c) {
        //
        // })
        // .on("mouseout", function() {  })

    // add the X Axis
    svg.append("g")
        .attr("class", "decayingGraphAxis")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis);

    // add the Y Axis
    svg.append("g")
        .attr("class", "decayingGraphAxis")
        .call(yAxis);


    function dragmove(d) {
        d3.select(this)
            .attr("cx", function() { return d3.event.x; })
            .attr("cy", function() { return d3.event.y; });
    }


    // var ctx = $('#decayGraph');
    // chart = new Chart(ctx, {
    //     type: 'line',
    //     data: {
    //         labels: genAxis(),
    //         datasets: [
    //             {
    //                 label: 'Decay over time',
    //                 data: genDecay(),
    //                 borderColor: 'rgba(91, 183, 91, 0.7)',
    //                 backgroundColor: 'rgba(91, 183, 91, 0.3)',
    //                 cubicInterpolationMode: 'monotone',
    //                 fill: 1,
    //                 pointRadius: 0
    //             },
    //             {
    //                 label: 'Threshold',
    //                 data: genLine(),
    //                 borderColor: 'rgba(255, 99, 132, 0.7)',
    //                 backgroundColor: 'rgba(255, 99, 132, 0.3)',
    //                 pointRadius: 0
    //             },
    //         ]
    //     },
    //     options: {
    //         responsive: true,
    //         title: {
    //             display: false
    //         },
    //         scales: {
    //             xAxes: [{
    //                 scaleLabel: {
    //                     display: true,
    //                     labelString: 'Days',
    //                 },
    //                 ticks: {
    //                     callback: function(hour, index, values) {
    //                         var d = parseInt(hour / 24);
    //                         return hour % 24 == 0 ? d : null;
    //                     }
    //                 }
    //             }],
    //             yAxes: [{
    //                 scaleLabel: {
    //                     display: true,
    //                     labelString: 'Decay Score',
    //                 },
    //                 ticks: {
    //                     suggestedMin: 0,
    //                     suggestedMax: 100
    //                 }
    //             }]
    //         },
    //         tooltips: {
    //             position: 'nearest',
    //             mode: 'index',
    //             intersect: false,
    //             callbacks: {
    //                 title: function(tooltipItem, data)  {
    //                     return hoursToText(tooltipItem[0].index);
    //                 },
    //                 label: function(tooltipItem, data)  {
    //                     var label = data.datasets[tooltipItem.datasetIndex].label;
    //                     if (label != 'Threshold') {
    //                         label = "Score";
    //                     }
    //                     label += ": " + data.datasets[tooltipItem.datasetIndex].data[tooltipItem.index];
    //                     return label;
    //                 }
    //             }
    //         },
    //     }
    // });
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
