<div>
    <div style="padding: 15px; height: 90vh; display: flex; flex-direction: column;">
        <div style="flex-grow: 3; display: flex">
            <div style="width: 30%; display: flex; flex-direction: column;">
                <div class="panel-container" style="display: flex; flex-direction: column; flex-grow: 1">
                    <ul class="nav nav-tabs" id="simulation-tabs">
                        <li class="active"><a href="#restsearch" data-toggle="tab">RestSearch</a></li>
                        <li><a href="#specificid" data-toggle="tab">Specific ID</a></li>
                    </ul>

                    <div class="tab-content">
                        <div class="tab-pane active" id="restsearch">
                            <h3 style="flex-grow: 0">Attribute RestSearch<span style="vertical-align: top; font-size: x-small;" class="fa fa-question-circle" title="Enforced fields: returnFormat"></span></h3>
                            <textarea style="flex-grow: 1; margin-bottom: 0px; width: auto;" value=""></textarea>
                        </div>
                        <div class="tab-pane" id="specificid">
                        </div>
                    </div>

                </div>
                <div style="flex-grow: 0">
                    <div class="panel-container">
                    </div>
                </div>
            </div>
            <div style="width: 70%; display: flex;">
                <div class="panel-container" style="flex-grow: 1;">
                </div>
            </div>
        </div>
        <div style="flex-grow: 7; overflow-y: auto;" class="panel-container">
            <table>
            </table>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {

});
</script>
