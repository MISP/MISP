<?php
    echo $this->Html->css('query-builder.default.min');
    echo $this->Html->css('datatables.min');
    echo $this->Html->script('jquery');
    echo $this->Html->script('datatables.min');
    echo $this->Html->script('query-builder.standalone.min');
?>
<div class="events form">
    <div id="builder"></div>                                                                                   
    <div class="btn-group">
        <button class="btn btn-warning reset" id="btn-reset" data-target="basic">Reset</button>                
        <button class="btn btn-primary parse-json" id="btn-get" data-target="basic">Search</button>
    </div> 
    <br/><br/>
    <div id="queryResults">
        <table id="result_table" class="table table-condensed table-striped table-bordered" style="font-size: 1.0em;">
            <thead>
                <tr>
                    <th>Published</th>
                    <th>Id</th>
                    <th>Org</th>
                    <th>Tags</th>
                    <th>#Attr.</th>
                    <th>Date</th>
                    <th>Info</th>
                    <th>Distribution</th>
                    <th>Actions</th>
                </tr>
            </thead>
        </table>
    </div>
</div>

<script type="text/javascript" language="javascript" class="init">
var result = null;
var csrftoken = getCookie('csrftoken');

var resTable = $('#result_table').dataTable({
    processing: true, serverSide: true, pageLength: 25,
    order: [[ 5, "desc" ]],
    deferLoading: 0,
    ajax: {
        processing: true,
	type: "POST",
	contentType: "application/json",
        url: "/events/search/",
        data: function ( d ) {
            var settings = $("#result_table").dataTable().fnSettings();
            var obj = {
                "draw" : settings.iDraw,
                "start" : settings._iDisplayStart,
                "length" : settings._iDisplayLength
            };
            var objfin = Object.assign(obj, result);
	    d.content = objfin;
	    return JSON.stringify(d);
        },
        dataSrc: "data",
        dataType: "json"
    },
    "rowCallback": function( row, data, index ) {},
    columns: [
        {'data': 'published', 'sName': 'Published', 'aTargets': [ 0 ], 'width': "20pt",
            "mRender": function (data, type, full) {
                var uri = '<?php echo $baseurl."/events/view/" ?>'+full.Id;
                if(full.published) {
                    return '<a href="'+uri+'" class = "icon-ok" title = "<?php echo __('View');?>"></a>';
                } else {
                    return '<a href="'+uri+'" class = "icon-remove" title = "<?php echo __('View');?>"></a>';
                }
            }
        },
        {'data': 'Id', 'sName': 'Id', 'aTargets': [ 1 ], 'width': "20pt",
            "mRender": function (data, type, full) {
                var uri = '<?php echo $baseurl."/events/view/" ?>'+full.Id;
                return '<a href="'+uri+'">'+full.Id+'</a>'
            }
        },
        {'data': 'Org', 'sName': 'Org', 'aTargets': [ 2 ], 'bSortable': false, 'width': "40pt"},
        {'data': 'Tags', 'sName': 'Tags', 'aTargets': [ 3 ], 'bSortable': false, 'width': "40pt"},
        {'data': 'Attr', 'sName': '#Attr.', 'aTargets': [ 4 ], 'width': "20pt"},
        {'data': 'Date', 'sName': 'Date', 'aTargets': [ 5 ], 'width': "40pt"},
        {'data': 'Info', 'sName': 'Info', 'aTargets': [ 6 ]},
        {'data': 'Distribution', 'sName': 'Distribution', 'aTargets': [ 7 ], 'width': "20pt",
            "mRender": function (data, type, full) {
                if(data == 0) {
                    return "Organisation";
                } else {
                    return data;
                }
            }
        },
        {'data': 'Actions', 'sName': 'Actions', 'aTargets': [ 8 ], 'bSortable': false, 'width': "20pt"},
    ]
});


var rules_basic = {
    condition: 'AND', // default condition
    rules: [{
    id: 'info'
    }]
};
    $('#builder').queryBuilder({
        // list of items to filter
        filters: [
            {
                id: 'info',
                label: 'Event Info',
                type: 'string'
            },
            {
                id: 'attribute_count',
                label: 'Attribute Count',
                type: 'integer'
            },
            {
                id: 'published',
                label: 'Published',
                type: 'boolean'
            },
        ],
        operators: ['equal', 'begins_with', 'not_begins_with', 'contains', 'ends_with', 'not_ends_with', 'less', 'greater'], // allowed filter operators
        rules: rules_basic
    });
    $('#btn-reset').on('click', function() {
        $('#builder').queryBuilder('reset');
    });
    $('#btn-get').on('click', function() {
        result = $('#builder').queryBuilder('getRules');
        if (!$.isEmptyObject(result)) {
            resTable.DataTable().draw();
        }
    });
    function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
    
    function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
    var cookies = document.cookie.split(';');
    for (var i = 0; i < cookies.length; i++) {
    var cookie = jQuery.trim(cookies[i]);
    // Does this cookie string begin with the name we want?
    if (cookie.substring(0, name.length + 1) === (name + '=')) {
    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
    break;
    }
    }
    }
    return cookieValue;
    }
</script>


<input type="hidden" class="keyboardShortcutsConfig" value="/shortcuts/event_index.json" />
<?php
    if (!$ajax) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'search'));
