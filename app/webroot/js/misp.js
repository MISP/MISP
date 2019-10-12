String.prototype.ucfirst = function() {
    return this.charAt(0).toUpperCase() + this.slice(1);
}

if (!String.prototype.startsWith) {
  String.prototype.startsWith = function(searchString, position) {
    position = position || 0;
    return this.indexOf(searchString, position) === position;
  };
}

function stringToRGB(str){
    var hash = 0;
    if (str.length == 0) return hash;
    for (i = 0; i < str.length; i++) {
        hash = ((hash<<5)-hash) + str.charCodeAt(i);
        hash = hash & hash; // Convert to 32bit integer
    }
    var c = (hash & 0x00FFFFFF)
        .toString(16)
        .toUpperCase();

    return "#" + "00000".substring(0, 6 - c.length) + c;
}

function deleteObject(type, action, id, event) {
    var destination = 'attributes';
    var alternateDestinations = ['shadow_attributes', 'template_elements', 'taxonomies', 'galaxy_clusters', 'objects', 'object_references'];
    if (alternateDestinations.indexOf(type) > -1) destination = type;
    else destination = type;
    url = "/" + destination + "/" + action + "/" + id;
    $.get(url, function(data) {
        openPopup("#confirmation_box");
        $("#confirmation_box").html(data);
    });
}

function quickDeleteSighting(id, rawId, context) {
    url = "/sightings/quickDelete/" + id + "/" + rawId + "/" + context;
    $.get(url, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function fetchAddSightingForm(type, attribute_id, page, onvalue) {
    var url = "/sightings/quickAdd/" + attribute_id + "/" + type;
    if (onvalue) {
        url = url + "/1";
    } else {
        url = url + "/0";
    }
    $.get(url, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function flexibleAddSighting(clicked, type, attribute_id, event_id, value, page, placement) {
    var $clicked = $(clicked);
    var hoverbroken = false;
    $clicked.off('mouseleave.temp').on('mouseleave.temp', function() {
        hoverbroken = true;
    });
    setTimeout(function() {
        $clicked.off('mouseleave.temp');
        if ($clicked.is(":hover") && !hoverbroken) {
            var html = '<div>'
                + '<button class="btn btn-primary" onclick="addSighting(\'' + type + '\', \'' + attribute_id + '\', \'' + event_id + '\', \'' + page + '\')">This attribute</button>'
                + '<button class="btn btn-primary" style="margin-left:5px;" onclick="fetchAddSightingForm(\'' + type + '\', \'' + attribute_id + '\', \'' + page + '\', true)">Global value</button>'
                + '</div>';
            openPopover(clicked, html, true, placement);
        }
    }, 1000);
}

function publishPopup(id, type) {
    var action = "alert";
    if (type == "publish") action = "publish";
    if (type == "unpublish") action = "unpublish";
    var destination = 'attributes';
    $.get( "/events/" + action + "/" + id, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function delegatePopup(id) {
    simplePopup("/event_delegations/delegateEvent/" + id);
}

function genericPopup(url, popupTarget, callback) {
    $.get(url, function(data) {
        $(popupTarget).html(data);
        $(popupTarget).fadeIn();
        left = ($(window).width() / 2) - ($(popupTarget).width() / 2);
        $(popupTarget).css({'left': left + 'px'});
        $("#gray_out").fadeIn();
        if (callback !== undefined) {
            callback();
        }
    });
}

function screenshotPopup(url, title) {
    if (!url.startsWith('data:image/')) {
        url = url.slice(0, -1);
    }
    popupHtml = '<it class="fa fa-spin fa-spinner" style="font-size: xx-large; color: white; position: fixed; left: 50%; top: 50%;"></it>';
    url = $('<div>').text(url).html();
    title = $('<div>').text(title).html();
    popupHtml += '<img class="screenshot_box-content hidden" src="' + url + '" id="screenshot-image" title="' + title + '" alt="' + title + '" onload="$(this).show(); $(this).parent().find(\'.fa-spinner\').remove();"/>';
    popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
    if (!url.startsWith('data:image/')) {
        popupHtml += '<a class="close-icon useCursorPointer fa fa-expand" style="right: 20px; background: black; color: white; text-decoration: none;" target="_blank" href="' + url + '" ></a>';
    }
    popupHtml += '<div style="height: 20px;"></div>'; // see bottom of image for large one
    $('#screenshot_box').html(popupHtml);
    $('#screenshot_box').css({
        display: 'block',
        top: (document.documentElement.scrollTop + 100) + 'px'
    });
    $("#gray_out").fadeIn();
}

function submitPublish(id, type) {
    $("#PromptForm").submit();
}

function editTemplateElement(type, id) {
    simplePopup("/template_elements/edit/" + type + "/" + id);
}

function cancelPrompt(isolated) {
    if (isolated == undefined) {
        $("#gray_out").fadeOut();
    }
    $("#confirmation_box").fadeOut();
    $("#confirmation_box").empty();
    $('.have-a-popover').popover('destroy');
}

function submitDeletion(context_id, action, type, id) {
    var context = 'event';
    if (type == 'template_elements') context = 'template';
    var formData = $('#PromptForm').serialize();
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: formData,
        success:function (data, textStatus) {
            if (type == 'eventGraph') {
                showMessage('success', 'Network has been deleted');
                reset_graph_history();
            } else {
                updateIndex(context_id, context);
                handleGenericAjaxResponse(data);
            }
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        cache: false,
        url:"/" + type + "/" + action + "/" + id,
    });
}

function removeSighting(caller) {
    var id = $(caller).data('id');
    var rawid = $(caller).data('rawid');
    var context = $(caller).data('context');
    if (context != 'attribute') {
        context = 'event';
    }
    var formData = $('#PromptForm').serialize();
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: formData,
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data);
            var org = "/" + $('#org_id').text();
            updateIndex(id, 'event');
            $.get( "/sightings/listSightings/" + rawid + "/" + context + org, function(data) {
                $("#sightingsData").html(data);
            });
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
        },
        type:"post",
        cache: false,
        url:"/sightings/quickDelete/" + id + "/" + rawid + "/" + context,
    });
}

function toggleSetting(e, setting, id) {
    e.preventDefault();
    e.stopPropagation();
    switch (setting) {
    case 'warninglist_enable':
        formID = '#WarninglistIndexForm';
        dataDiv = '#WarninglistData';
        replacementForm = '/warninglists/getToggleField/';
        searchString = 'enabled';
        break;
    case 'favourite_tag':
        formID = '#FavouriteTagIndexForm';
        dataDiv = '#FavouriteTagData';
        replacementForm = '/favourite_tags/getToggleField/';
        searchString = 'Adding';
        break;
    case 'activate_object_template':
        formID = '#ObjectTemplateIndexForm';
        dataDiv = '#ObjectTemplateData';
        replacementForm = '/ObjectTemplates/getToggleField/';
        searchString = 'activated';
        break;
    case 'noticelist_enable':
        formID = '#NoticelistIndexForm';
        dataDiv = '#NoticelistData';
        replacementForm = '/noticelists/getToggleField/';
        searchString = 'enabled';
        break;
    }
    $(dataDiv).val(id);
    var formData = $(formID).serialize();
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: formData,
        success:function (data, textStatus) {
            var result = data;
            if (result.success) {
                var setting = false;
                if (result.success.indexOf(searchString) > -1) setting = true;
                $('#checkBox_' + id).prop('checked', setting);
            }
            handleGenericAjaxResponse(data);
        },
        complete:function() {
            $.get(replacementForm, function(data) {
                $('#hiddenFormDiv').html(data);
            });
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        error:function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Request failed due to an unexpected error.']});
        },
        type:"post",
        cache: false,
        url: $(formID).attr('action'),
    });
}

function initiatePasswordReset(id) {
    $.get( "/users/initiatePasswordReset/" + id, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function submitPasswordReset(id) {
    var formData = $('#PromptForm').serialize();
    var url = "/users/initiatePasswordReset/" + id;
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: formData,
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data);
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        cache: false,
        url:url,
    });
}

function submitMessageForm(url, form, target) {
    if (!$('#PostMessage').val()) {
        showMessage("fail", "Cannot submit empty message.");
    } else {
        submitGenericForm(url, form, target);
    }
}

function submitGenericForm(url, form, target) {
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: $('#' + form).serialize(),
        success:function (data, textStatus) {
            $('#top').html(data);
            showMessage("success", "Message added.");
        },
        complete:function() {
            $(".loading").hide();
        },
        type:"post",
        cache: false,
        url:url,
    });
}

function acceptObject(type, id, event) {
    name = '#ShadowAttribute_' + id + '_accept';
    var formData = $(name).serialize();
    $.ajax({
        data: formData,
        success:function (data, textStatus) {
            updateIndex(event, 'event');
            eventUnpublish();
            handleGenericAjaxResponse(data);
        },
        type:"post",
        cache: false,
        url:"/shadow_attributes/accept/" + id,
    });
}

function toggleCorrelation(id, skip_reload) {
    if (typeof skip_reload === "undefined") {
        skip_reload = false;
    }
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: $('#PromptForm').serialize(),
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data, skip_reload);
            $("#correlation_toggle_" + id).prop('checked', !$("#correlation_toggle_" + id).is(':checked'));
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        cache: false,
        url:'/attributes/toggleCorrelation/' + id,
    });
}

function toggleToIDS(id, skip_reload) {
    if (typeof skip_reload === "undefined") {
        skip_reload = false;
    }
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: $('#PromptForm').serialize(),
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data, skip_reload);
            $("#toids_toggle_" + id).prop('checked', !$("#toids_toggle_" + id).is(':checked'));
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        cache: false,
        url:'/attributes/editField/' + id ,
    });
}

function eventUnpublish() {
    $('.publishButtons').show();
    $('.exportButtons').hide();
    $('.published').hide();
    $('.notPublished').show();
}

function updateIndex(id, context, newPage) {
    if (typeof newPage !== 'undefined') page = newPage;
    var url, div;
    if (context == 'event') {
        if (typeof currentUri == 'undefined') {
            location.reload();
            return true;
        }
        url = currentUri;
        div = "#attributes_div";
    }
    if (context == 'template') {
        url = "/template_elements/index/" + id;
        div = "#templateElements";
    }
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $(div).html(data);
            if (typeof genericPopupCallback !== "undefined") {
                genericPopupCallback("success");
            } else {
                console.log("genericPopupCallback function not defined");
            }
        },
        url: url,
    });
}

function updateAttributeFieldOnSuccess(name, type, id, field, event) {
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            if (field != 'timestamp') {
                $(".loading").show();
            }
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            if (field != 'timestamp') {
                $(".loading").hide();
                $(name + '_solid').html(data);
                $(name + '_placeholder').empty();
                $(name + '_solid').show();
            } else {
                $('#' + type + '_' + id + '_' + 'timestamp_solid').html(data);
            }
        },
        url:"/attributes/fetchViewValue/" + id + "/" + field,
    });
}

function activateField(type, id, field, event) {
    resetForms();
    if (type == 'denyForm') return;
    var objectType = 'attributes';
    if (type == 'ShadowAttribute') {
        objectType = 'shadow_attributes';
    }
    var name = '#' + type + '_' + id + '_' + field;
    var container_name = '#Attribute_' + id + '_' + field;
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $(container_name + '_placeholder').html(data);
            postActivationScripts(name, type, id, field, event);
        },
        url:"/" + objectType + "/fetchEditForm/" + id + "/" + field,
    });
}


function submitQuickTag(form) {
    $('#' + form).submit();
}

//if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
//If a user presses enter, submit the form
function postActivationScripts(name, type, id, field, event) {
    $(name + '_field').focus();
    inputFieldButtonActive(name + '_field');
    if (field == 'value' || field == 'comment') {
        autoresize($(name + '_field')[0]);
        $(name + '_field').on('keyup', function () {
            autoresize(this);
        });
    }
    $(name + '_form').submit(function(e){
        e.preventDefault();
        submitForm(type, id, field, event);
        return false;
    });

    $(name + '_form').bind("focusout", function() {
        inputFieldButtonPassive(name + '_field');
    });

    $(name + '_form').bind("focusin", function(){
        inputFieldButtonActive(name + '_field');
    });

    $(name + '_form').bind("keydown", function(e) {
        if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
            submitForm(type, id, field, event);
        }
    });
    $(name + '_field').closest('.inline-input-container').children('.inline-input-accept').bind('click', function() {
        submitForm(type, id, field, event);
    });

    $(name + '_field').closest('.inline-input-container').children('.inline-input-decline').bind('click', function() {
        resetForms();
    });

    $(name + '_solid').hide();
}

function quickEditHover(td, type, id, field, event) {
    var $td = $(td);
    $td.find('#quickEditButton').remove(); // clean all similar if exist
    var $div = $('<div id="quickEditButton"></div>');
    $div.addClass('quick-edit-row-div');
    var $span = $('<span></span>');
    $span.addClass('fa-as-icon fa fa-edit');
    $span.css('font-size', '12px');
    $div.append($span);
    $td.find("[id*=_solid]").append($div);

    $span.click(function() {
        activateField(type, id, field, event);
    });

    $td.off('mouseleave').on('mouseleave', function() {
        $div.remove();
    });
}

function addSighting(type, attribute_id, event_id, page) {
    $('#Sighting_' + attribute_id + '_type').val(type);
    $.ajax({
        data: $('#Sighting_' + attribute_id).closest("form").serialize(),
        cache: false,
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data);
            var result = data;
            if (result.saved == true) {
                $('.sightingsCounter').each(function( counter ) {
                    $(this).html(parseInt($(this).html()) + 1);
                });
                if (typeof currentUri == 'undefined') {
                    location.reload();
                } else {
                    updateIndex(event_id, 'event');
                }
            }
        },
        error:function() {
            showMessage('fail', 'Request failed for an unknown reason.');
            updateIndex(context, 'event');
        },
        type:"post",
        url:"/sightings/add/" + attribute_id
    });
}

function resetForms() {
    $('.inline-field-solid').show();
    $('.inline-field-placeholder').empty();
}

function inputFieldButtonActive(selector) {
    $(selector).closest('.inline-input-container').children('.inline-input-accept').removeClass('inline-input-passive').addClass('inline-input-active');
    $(selector).closest('.inline-input-container').children('.inline-input-decline').removeClass('inline-input-passive').addClass('inline-input-active');
}

function inputFieldButtonPassive(selector) {
    $(selector).closest('.inline-input-container').children('.inline-input-accept').addClass('inline-input-passive').removeClass('inline-input-active');
    $(selector).closest('.inline-input-container').children('.inline-input-daecline').addClass('inline-input-passive').removeClass('inline-input-active');
}

function autoresize(textarea) {
    textarea.style.height = '20px';
    textarea.style.height = (textarea.scrollHeight) + 'px';
}

// submit the form - this can be triggered by unfocusing the activated form field or by submitting the form (hitting enter)
// after the form is submitted, intercept the response and act on it
function submitForm(type, id, field, context) {
    var object_type = 'attributes';
    var action = "editField";
    var name = '#' + type + '_' + id + '_' + field;
    if (type == 'ShadowAttribute') {
        object_type = 'shadow_attributes';
    }
    $.ajax({
        data: $(name + '_field').closest("form").serialize(),
        cache: false,
        success:function (data, textStatus) {
            handleAjaxEditResponse(data, name, type, id, field, context);
        },
        error:function() {
            showMessage('fail', 'Request failed for an unknown reason.');
            updateIndex(context, 'event');
        },
        type:"post",
        url:"/" + object_type + "/" + action + "/" + id
    });
    $(name + '_field').unbind("keyup");
    $(name + '_form').unbind("focusout");
    return false;
};

function quickSubmitTagForm(selected_tag_ids, addData) {
    var event_id = addData.id;
    var localFlag = '';
    if (undefined != addData['local'] && addData['local']) {
        localFlag = '/local:1';
    }
    url = "/events/addTag/" + event_id + localFlag;
    fetchFormDataAjax(url, function(formData) {
        $('body').append($('<div id="temp"/>').html(formData));
        $('#temp #EventTag').val(JSON.stringify(selected_tag_ids));
        $.ajax({
            data: $('#EventAddTagForm').serialize(),
            cache: false,
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            success:function (data, textStatus) {
                loadEventTags(event_id);
                loadGalaxies(event_id, 'event');
                handleGenericAjaxResponse(data);
            },
            error:function() {
                showMessage('fail', 'Could not add tag.');
                loadEventTags(event_id);
                loadGalaxies(event_id, 'event');
            },
            complete:function() {
                $('#temp').remove();
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
                $('#temp').remove();
            },
            type:"post",
            url:url
        });
    });
}

function quickSubmitAttributeTagForm(selected_tag_ids, addData) {
    var attribute_id = addData.id;
    var localFlag = '';
    if (undefined != addData['local'] && addData['local']) {
        localFlag = '/local:1';
    }
    url = "/attributes/addTag/" + attribute_id + localFlag;
    fetchFormDataAjax(url, function(formData) {
        $('body').append($('<div id="temp"/>').html(formData));
        $('#temp #AttributeTag').val(JSON.stringify(selected_tag_ids));
        if (attribute_id == 'selected') {
            $('#AttributeAttributeIds').val(getSelected());
        }
        $.ajax({
            data: $('#AttributeAddTagForm').serialize(),
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            success:function (data, textStatus) {
                if (attribute_id == 'selected') {
                    updateIndex(0, 'event');
                } else {
                    loadAttributeTags(attribute_id);
                    loadGalaxies(attribute_id, 'attribute');
                }
                handleGenericAjaxResponse(data);
            },
            error:function() {
                showMessage('fail', 'Could not add tag.');
                loadAttributeTags(attribute_id);
                loadGalaxies(attribute_id, 'attribute');
            },
            complete:function() {
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
                $('#temp').remove();
            },
            type:"post",
            url: url
        });
    });
}

function quickSubmitTagCollectionTagForm(selected_tag_ids, addData) {
    var tag_collection_id = addData.id;
    var localFlag = '';
    if (undefined != addData['local'] && addData['local']) {
        localFlag = '/local:1';
    }
    url = "/tag_collections/addTag/" + tag_collection_id + localFlag;
    fetchFormDataAjax(url, function(formData) {
        $('body').append($('<div id="temp"/>').html(formData));
        $('#temp #TagCollectionTag').val(JSON.stringify(selected_tag_ids));
        $.ajax({
            data: $('#TagCollectionAddTagForm').serialize(),
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            success:function (data, textStatus) {
                handleGenericAjaxResponse(data);
                refreshTagCollectionRow(tag_collection_id);
            },
            error:function() {
                showMessage('fail', 'Could not add tag.');
                loadTagCollectionTags(tag_collection_id);
            },
            complete:function() {
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
                $('#temp').remove();
            },
            type:"post",
            url: url
        });
    });
}

function refreshTagCollectionRow(tag_collection_id) {
    $.ajax({
        type:"get",
        url:"/tag_collections/getRow/" + tag_collection_id,
        error:function() {
            showMessage('fail', 'Could not fetch updates to the modified row.');
        },
        success: function (data, textStatus) {
            $('[data-row-id="' + tag_collection_id + '"]').replaceWith(data);
        }
    });

}

function handleAjaxEditResponse(data, name, type, id, field, event) {
    responseArray = data;
    if (type == 'Attribute') {
        if (responseArray.saved) {
            showMessage('success', responseArray.success);
            updateAttributeFieldOnSuccess(name, type, id, field, event);
            updateAttributeFieldOnSuccess(name, type, id, 'timestamp', event);
            eventUnpublish();
        } else {
            showMessage('fail', 'Validation failed: ' + responseArray.errors.value);
            updateAttributeFieldOnSuccess(name, type, id, field, event);
        }
    }
    if (type == 'ShadowAttribute') {
        updateIndex(event, 'event');
    }
    if (responseArray.hasOwnProperty('check_publish')) {
        checkAndSetPublishedInfo();
    }
}

function handleGenericAjaxResponse(data, skip_reload) {
    if (typeof skip_reload === "undefined") {
        skip_reload = false;
    }
    if (typeof data == 'string') {
        responseArray = JSON.parse(data);
    } else {
        responseArray = data;
    }

    // remove remaining popovers
    cancelPrompt();
    // in case the origin node has been deleted (e.g. tags)
    $('.popover').remove();

    if (responseArray.saved) {
        showMessage('success', responseArray.success);
        if (responseArray.hasOwnProperty('check_publish')) {
            checkAndSetPublishedInfo(skip_reload);
        }
        return true;
    } else {
        showMessage('fail', responseArray.errors);
        return false;
    }
}

function toggleAllAttributeCheckboxes() {
    if ($(".select_all").is(":checked")) {
        $(".select_attribute").prop("checked", true);
        $(".select_proposal").prop("checked", true);
    } else {
        $(".select_attribute").prop("checked", false);
        $(".select_proposal").prop("checked", false);
    }
}

function toggleAllCheckboxes() {
    if ($(".select_all").is(":checked")) {
        $(".select").prop("checked", true);
    } else {
        $(".select").prop("checked", false);
    }
}

function toggleAllTaxonomyCheckboxes() {
    if ($(".select_all").is(":checked")) {
        $(".select_taxonomy").prop("checked", true);
    } else {
        $(".select_taxonomy").prop("checked", false);
    }
}

function attributeListAnyAttributeCheckBoxesChecked() {
    if ($('.select_attribute:checked').length > 0) $('.mass-select').removeClass('hidden');
    else $('.mass-select').addClass('hidden');
}

function listCheckboxesChecked() {
    if ($('.select:checked').length > 0) $('.mass-select').removeClass('hidden');
    else $('.mass-select').addClass('hidden');
}

function attributeListAnyProposalCheckBoxesChecked() {
    if ($('.select_proposal:checked').length > 0) $('.mass-proposal-select').removeClass('hidden');
    else $('.mass-proposal-select').addClass('hidden');
}

function taxonomyListAnyCheckBoxesChecked() {
    if ($('.select_taxonomy:checked').length > 0) $('.mass-select').show();
    else $('.mass-select').hide();
}

function multiSelectDeleteEvents() {
    var selected = [];
    $(".select").each(function() {
        if ($(this).is(":checked")) {
            var temp = $(this).data("id");
            if (temp != null) {
                selected.push(temp);
            }
        }
    });
    $.get("/events/delete/" + JSON.stringify(selected), function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function multiSelectToggleFeeds(on, cache) {
    var selected = [];
    $(".select").each(function() {
        if ($(this).is(":checked")) {
            var temp = $(this).data("id");
            if (temp != null) {
                selected.push(temp);
            }
        }
    });
    $.get("/feeds/toggleSelected/" + on + "/" + cache + "/" + JSON.stringify(selected), function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function multiSelectDeleteEventBlacklist(on, cache) {
    var selected = [];
    $(".select").each(function() {
        if ($(this).is(":checked")) {
            var temp = $(this).data("id");
            if (temp != null) {
                selected.push(temp);
            }
        }
    });
    $.get("/eventBlacklists/massDelete?ids=" + JSON.stringify(selected), function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function multiSelectAction(event, context) {
    var settings = {
            deleteAttributes: {
                confirmation: "Are you sure you want to delete all selected attributes?",
                controller: "attributes",
                camelCase: "Attribute",
                alias: "attribute",
                action: "delete"
            },
            acceptProposals: {
                confirmation: "Are you sure you want to accept all selected proposals?",
                controller: "shadow_attributes",
                camelCase: "ShadowAttribute",
                alias: "proposal",
                action: "accept"
            },
            discardProposals: {
                confirmation: "Are you sure you want to discard all selected proposals?",
                controller: "shadow_attributes",
                camelCase: "ShadowAttribute",
                alias: "proposal",
                action: "discard"
            },
    };
    var answer = confirm("Are you sure you want to " + settings[context]["action"] + " all selected " + settings[context]["alias"] + "s?");
    if (answer) {
        var selected = [];
        $(".select_" + settings[context]["alias"]).each(function() {
            if ($(this).is(":checked")) {
                var temp= $(this).data("id");
                selected.push(temp);
            }
        });
        $('#' + settings[context]["camelCase"] + 'Ids' + settings[context]["action"].ucfirst()).attr('value', JSON.stringify(selected));
        var formData = $('#' + settings[context]["action"] + '_selected').serialize();
        if (context == 'deleteAttributes') {
            var url = $('#delete_selected').attr('action');
            console.log(url);
        } else {
            var url = "/" + settings[context]["controller"] + "/" + settings[context]["action"] + "Selected/" + event;
        }
        $.ajax({
            data: formData,
            cache: false,
            type:"POST",
            url: url,
            success:function (data, textStatus) {
                updateIndex(event, 'event');
                var result = handleGenericAjaxResponse(data);
                if (settings[context]["action"] != "discard" && result == true) eventUnpublish();
            },
        });
    }
    return false;
}

function editSelectedAttributes(event) {
    var selectedAttributeIds = getSelected();
    simplePopup("/attributes/editSelected/" + event + "/" + selectedAttributeIds);
}

function addSelectedTaxonomies(taxonomy) {
    $.get("/taxonomies/taxonomyMassConfirmation/"+taxonomy, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function proposeObjectsFromSelectedAttributes(clicked, event_id) {
    var selectedAttributeIds = getSelected();
    popoverPopup(clicked, event_id + '/' + selectedAttributeIds, 'objects', 'proposeObjectsFromAttributes');
}

function hideSelectedTags(taxonomy) {
	$.get("/taxonomies/taxonomyMassHide/"+taxonomy, function(data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
}

function unhideSelectedTags(taxonomy) {
	$.get("/taxonomies/taxonomyMassUnhide/"+taxonomy, function(data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
}

function submitMassTaxonomyTag() {
    $('#PromptForm').submit();
}

function submitMassEventDelete() {
    $('#PromptForm').trigger('submit');
    event.preventDefault();
}

function getSelected() {
    var selected = [];
    $(".select_attribute").each(function() {
        if ($(this).is(":checked")) {
            var test = $(this).data("id");
            selected.push(test);
        }
    });
    return JSON.stringify(selected);
}

function getSelectedTaxonomyNames() {
    var selected = [];
    $(".select_taxonomy").each(function() {
        if ($(this).is(":checked")) {
            var row = $(this).data("id");
            var temp = $('#tag_' + row).html();
            temp = $("<div/>").html(temp).text();
            selected.push(temp);
        }
    });
    $('#TaxonomyNameList').val(JSON.stringify(selected));
}

function loadEventTags(id) {
    $.ajax({
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".eventTagContainer").html(data);
        },
        url:"/tags/showEventTag/" + id,
    });
}

function loadGalaxies(id, scope) {
    $.ajax({
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            if (scope == 'event') {
                $("#galaxies_div").html(data);
            } else if (scope == 'attribute') {
                $("#attribute_" + id + "_galaxy").html(data);
            }
        },
        url:"/galaxies/showGalaxies/" + id + "/" + scope,
    });
}

function loadTagCollectionTags(id) {
    $.ajax({
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".tagCollectionTagContainer").html(data);
        },
        url:"/tags/showEventTag/" + id,
    });
}

function removeEventTag(event, tag) {
    var answer = confirm("Are you sure you want to remove this tag from the event?");
    if (answer) {
        var formData = $('#removeTag_' + tag).serialize();
        $.ajax({
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            data: formData,
            type:"POST",
            cache: false,
            url:"/events/removeTag/" + event + '/' + tag,
            success:function (data, textStatus) {
                loadEventTags(event);
                handleGenericAjaxResponse(data);
            },
            complete:function() {
                $(".loading").hide();
            }
        });
    }
    return false;
}

function loadAttributeTags(id) {
    $.ajax({
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $("#Attribute_"+id+"_tr .attributeTagContainer").html(data);
        },
        url:"/tags/showAttributeTag/" + id
    });
}

function removeObjectTagPopup(clicked, context, object, tag) {
    $.get( "/" + context + "s/removeTag/" + object + '/' + tag, function(data) {
        openPopover(clicked, data);
    });
}

function removeObjectTag(context, object, tag) {
    var formData = $('#PromptForm').serialize();
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: formData,
        type:"POST",
        cache: false,
        url:"/" + context.toLowerCase() + "s/removeTag/" + object + '/' + tag,
        success:function (data, textStatus) {
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
            if (context == 'Attribute') {
                loadAttributeTags(object);
            } else if (context == 'tag_collection') {
                refreshTagCollectionRow(object);
            } else {
                loadEventTags(object);
            }
            handleGenericAjaxResponse(data);
        },
        complete:function() {
            $(".loading").hide();
        }
    });
    return false;
}

function redirectAddObject(templateId, additionalData) {
    var eventId = additionalData['event_id'];
    window.location = '/objects/add/' + eventId + '/' + templateId;
}

function clickCreateButton(event, type) {
    var destination = 'attributes';
    if (type == 'Proposal') destination = 'shadow_attributes';
    simplePopup("/" + destination + "/add/" + event);
}

function submitPopoverForm(context_id, referer, update_context_id) {
    var url = null;
    var context = 'event';
    var contextNamingConvention = 'Attribute';
    var closePopover = true;
    switch (referer) {
        case 'add':
            url = "/attributes/add/" + context_id;
            break;
        case 'edit':
            url = "/attributes/edit/" + context_id;
            break;
        case 'propose':
            url = "/shadow_attributes/add/" + context_id;
            break;
        case 'massEdit':
            url = "/attributes/editSelected/" + context_id;
            break;
        case 'addTextElement':
            url = "/templateElements/add/text/" + context_id;
            context = 'template';
            contextNamingConvention = 'TemplateElementText';
            break;
        case 'editTextElement':
            url = "/templateElements/edit/text/" + context_id;
            context = 'template';
            context_id = update_context_id;
            contextNamingConvention = 'TemplateElementText';
            break;
        case 'addAttributeElement':
            url = "/templateElements/add/attribute/" + context_id;
            context = 'template';
            contextNamingConvention = 'TemplateElementAttribute';
            break;
        case 'editAttributeElement':
            url = "/templateElements/edit/attribute/" + context_id;
            context = 'template';
            context_id = update_context_id;
            contextNamingConvention = 'TemplateElementAttribute';
            break;
        case 'addFileElement':
            url = "/templateElements/add/file/" + context_id;
            context = 'template';
            contextNamingConvention = 'TemplateElementFile';
            break;
        case 'editFileElement':
            url = "/templateElements/edit/file/" + context_id;
            context = 'template';
            context_id = update_context_id;
            contextNamingConvention = 'TemplateElementFile';
            break;
        case 'replaceAttributes':
            url = "/attributes/attributeReplace/" + context_id;
            break;
        case 'addSighting':
            url = "/sightings/add/" + context_id;
            closePopover = false;
            break;
        case 'addObjectReference':
            url = "/objectReferences/add/" + context_id;
            break;
    }
    if (url !== null) {
        url = baseurl + url;
        $.ajax({
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
                if (closePopover) {
                    $("#gray_out").fadeOut();
                    $("#popover_form").fadeOut();
                }
            },
            data: $("#submitButton").closest("form").serialize(),
            success:function (data, textStatus) {
                var result;
                if (closePopover) {
                    result = handleAjaxPopoverResponse(data, context_id, url, referer, context, contextNamingConvention);
                }
                if (referer == 'addSighting') {
                    updateIndex(update_context_id, 'event');
                    $.get( "/sightings/listSightings/" + id + "/attribute", function(data) {
                        $("#sightingsData").html(data);
                    });
                    $('.sightingsToggle').removeClass('btn-primary');
                    $('.sightingsToggle').addClass('btn-inverse');
                    $('#sightingsListAllToggle').removeClass('btn-inverse');
                    $('#sightingsListAllToggle').addClass('btn-primary');
                }
                if (context == 'event' && (referer == 'add' || referer == 'massEdit' || referer == 'replaceAttributes' || referer == 'addObjectReference')) eventUnpublish();
            },
            error: function (jqXHR, textStatus, errorThrown) {
                showMessage('fail', textStatus + ": " + errorThrown);
            },
            complete: function () {
                $(".loading").hide();
            },
            type: "post",
            url: url,
        });
    }

    return false;
};

function handleAjaxPopoverResponse(response, context_id, url, referer, context, contextNamingConvention) {
    responseArray = response;
    var message = null;
    var result = "fail";
    if (responseArray.saved) {
        updateIndex(context_id, context);
        if (responseArray.success) {
            showMessage("success", responseArray.success);
            result = "success";
        }
        if (responseArray.errors) {
            showMessage("fail", responseArray.errors);
        }
    } else {
        var savedArray = saveValuesForPersistance();
        $.ajax({
            async:true,
            dataType:"html",
            success:function (data, textStatus) {
                $("#popover_form").html(data);
                openPopup("#popover_form");
                var error_context = context.charAt(0).toUpperCase() + context.slice(1);
                handleValidationErrors(responseArray.errors, context, contextNamingConvention);
                result = "success";
                if (!$.isEmptyObject(responseArray)) {
                    result = "fail";
                    $("#formWarning").show();
                    $("#formWarning").html('The object(s) could not be saved. Please, try again.');
                }
                recoverValuesFromPersistance(savedArray);
                $(".loading").hide();
            },
            url:url
        });
    }
    return result;
}

//before we update the form (in case the action failed), we want to retrieve the data from every field, so that we can set the fields in the new form that we fetch
function saveValuesForPersistance() {
    var formPersistanceArray = new Array();
    for (i = 0; i < fieldsArray.length; i++) {
        formPersistanceArray[fieldsArray[i]] = $('#' + fieldsArray[i]).val();
    }
    return formPersistanceArray;
}

function recoverValuesFromPersistance(formPersistanceArray) {
    for (i = 0; i < fieldsArray.length; i++) {
        $('#' + fieldsArray[i]).val(formPersistanceArray[fieldsArray[i]]);
    }
}

function handleValidationErrors(responseArray, context, contextNamingConvention) {
    for (var k in responseArray) {
        var elementName = k.charAt(0).toUpperCase() + k.slice(1);
        $("#" + contextNamingConvention + elementName).parent().addClass("error");
        $("#" + contextNamingConvention + elementName).parent().append("<div class=\"error-message\">" + responseArray[k] + "</div>");
    }
}

function toggleHistogramType(type, old) {
    var done = false;
    old.forEach(function(entry) {
        if (type == entry) {
            done = true;
            old.splice(old.indexOf(entry), 1);
        }
    });
    if (done == false) old.push(type);
    updateHistogram(JSON.stringify(old));
}

function updateHistogram(selected) {
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $("#histogram").html(data);
        },
        url:"/users/histogram/" + selected,
    });
}

function showMessage(success, message, context) {
    if (typeof context !== "undefined") {
        $("#ajax_" + success, window.parent.document).html(message);
        var duration = 1000 + (message.length * 40);
        $("#ajax_" + success + "_container", window.parent.document).fadeIn("slow");
        $("#ajax_" + success + "_container", window.parent.document).delay(duration).fadeOut("slow");
    }
    $("#ajax_" + success).html(message);
    var duration = 1000 + (message.length * 40);
    $("#ajax_" + success + "_container").fadeIn("slow");
    $("#ajax_" + success + "_container").delay(duration).fadeOut("slow");
}

function cancelPopoverForm(id) {
    $("#gray_out").fadeOut();
    $("#popover_form").fadeOut();
    $("#popover_form_large").fadeOut();
    $("#screenshot_box").fadeOut();
    $("#popover_box").fadeOut();
    $("#confirmation_box").fadeOut();
    $('#gray_out').fadeOut();
    $('#popover_form').fadeOut();
    if (id !== undefined && id !== '') {
        $(id).fadeOut();
    }
}

function activateTagField() {
    $("#addTagButton").hide();
    $("#addTagField").show();
}

function tagFieldChange() {
    if ($("#addTagField :selected").val() > 0) {
        var selected_id = $("#addTagField :selected").val();
        var selected_text = $("#addTagField :selected").text();
        if ($.inArray(selected_id, selectedTags)==-1) {
            selectedTags.push(selected_id);
            appendTemplateTag(selected_id);
        }
    }
    $("#addTagButton").show();
    $("#addTagField").hide();
}

function appendTemplateTag(selected_id) {
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $("#tags").append(data);
        },
        url:"/tags/viewTag/" + selected_id,
    });
    updateSelectedTags();
}

function addAllTags(tagArray) {
    parsedTagArray = JSON.parse(tagArray);
    parsedTagArray.forEach(function(tag) {
        appendTemplateTag(tag);
    });
}

function removeTemplateTag(id, name) {
    selectedTags.forEach(function(tag) {
        if (tag == id) {
            var index = selectedTags.indexOf(id);
            if (index > -1) {
                selectedTags.splice(index, 1);
                updateSelectedTags();
            }
        }
    });
    $('#tag_bubble_' + id).remove();
}

function updateSelectedTags() {
    $('#hiddenTags').attr("value", JSON.stringify(selectedTags));
}

function saveElementSorting(order) {
    $.ajax({
        data: order,
        dataType:"json",
        contentType: "application/json",
        cache: false,
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data);
        },
        type:"post",
        cache: false,
        url:"/templates/saveElementSorting/",
    });
}

function templateAddElementClicked(id) {
    simplePopup("/template_elements/templateElementAddChoices/" + id);
}

function templateAddElement(type, id) {
    simplePopup("/template_elements/add/" + type + "/" + id);
}

function templateUpdateAvailableTypes() {
    $("#innerTypes").empty();
    var type = $("#TemplateElementAttributeType option:selected").text();
    var complex = $('#TemplateElementAttributeComplex:checked').val();
    if (complex && type != 'Select Type') {
        currentTypes.forEach(function(entry) {
            $("#innerTypes").append("<div class=\"templateTypeBox\" id=\"" + entry + "TypeBox\">" + entry + "</div>");
        });
        $('#outerTypes').show();
    }
    else $('#outerTypes').hide();
}

function populateTemplateTypeDropdown() {
    var cat = $("#TemplateElementAttributeCategory option:selected").text();
    currentTypes = [];
    if (cat == 'Select Category') {
        $('#TemplateElementAttributeType').html("<option>Select Type</option>");
    } else {
        var complex = $('#TemplateElementAttributeComplex:checked').val();
        if (cat in typeGroupCategoryMapping) {
            $('#TemplateElementAttributeType').html("<option>Select Type</option>");
            typeGroupCategoryMapping[cat].forEach(function(entry) {
                $('#TemplateElementAttributeType').append("<option>" + entry + "</option>");
            });
        } else {
            complex = false;
        }
        if (!complex) {
            $('#TemplateElementAttributeType').html("<option>Select Type</option>");
            categoryTypes[cat].forEach(function(entry) {
                $('#TemplateElementAttributeType').append("<option>" + entry + "</option>");
            });
        }
    }
}

function templateElementAttributeTypeChange() {
    var complex = $('#TemplateElementAttributeComplex:checked').val();
    var type = $("#TemplateElementAttributeType option:selected").text();
    currentTypes = [];
    if (type != 'Select Type') {
        if (complex) {
            complexTypes[type]["types"].forEach(function(entry) {
                currentTypes.push(entry);
            });
        } else {
            currentTypes.push(type);
        }
    } else {
        currentTypes = [];
    }
    $("#typeJSON").html(JSON.stringify(currentTypes));
    templateUpdateAvailableTypes();
}

function templateElementAttributeCategoryChange(category) {
    if (category in typeGroupCategoryMapping) {
        $('#complexToggle').show();
    } else {
        $('#complexToggle').hide();
    }
    if (category != 'Select Type') {
        populateTemplateTypeDropdown();
    }
    templateUpdateAvailableTypes();
}

function templateElementFileCategoryChange(category) {
    if (category == '') {
        $("#TemplateElementFileMalware")[0].disabled = true;
        $("#TemplateElementFileMalware")[0].checked = false;
    } else {
        if (categoryArray[category].length == 2) {
            $("#TemplateElementFileMalware")[0].disabled = false;
            $("#TemplateElementFileMalware")[0].checked = true;
        } else {
            $("#TemplateElementFileMalware")[0].disabled = true;
            if (categoryArray[category] == 'attachment') $("#TemplateElementFileMalware")[0].checked = false;
            else $("#TemplateElementFileMalware")[0].checked = true;
        }
    }
}

function openPopup(id, adjust_layout, callback) {
    adjust_layout = adjust_layout === undefined ? true : adjust_layout;
    if (adjust_layout) {
        var window_height = $(window).height();
        var popup_height = $(id).height();
        if (window_height < popup_height) {
            $(id).css("top", 50);
            $(id).css("height", window_height);
            $(id).addClass('vertical-scroll');
        } else {
            if (window_height > (300 + popup_height)) {
                var top_offset = ((window_height - popup_height) / 2) - 150;
            } else {
                var top_offset = (window_height - popup_height) / 2;
            }
            $(id).css("top", top_offset + 'px');
        }
    }
    $("#gray_out").fadeIn();
    $(id).fadeIn(400, function() {
        if (callback !== undefined) {
            callback();
        }
    });
}

function openPopover(clicked, data, hover, placement, callback) {
    hover = hover === undefined ? false : hover;
    placement = placement === undefined ? 'right' : placement;
    /* popup handling */
    var $clicked = $(clicked);
    var randomId = $clicked.attr('data-dismissid') !== undefined ? $clicked.attr('data-dismissid') : Math.random().toString(36).substr(2,9); // used to recover the button that triggered the popover (so that we can destroy the popover)
    var loadingHtml = '<div style="height: 75px; width: 75px;"><div class="spinner"></div><div class="loadingText">Loading</div></div>';
    $clicked.attr('data-dismissid', randomId);
    var closeButtonHtml = '<button type="button" class="close" style="margin-left: 5px;" onclick="$(&apos;[data-dismissid=&quot;' + randomId + '&quot;]&apos;).popover(\'hide\');">×</button>';

    if (!$clicked.data('popover')) {
        $clicked.addClass('have-a-popover');
        var popoverOptions = {
            html: true,
            placement: placement,
            trigger: 'manual',
            content: loadingHtml,
            container: 'body',
            template: '<div class="popover" role="tooltip" data-dismissid="' + randomId + '"><div class="arrow"></div><h3 class="popover-title"></h3><div class="popover-content"><div class="data-content"></div></div></div>'
        };
        $clicked.popover(popoverOptions)
        .on('shown.bs.popover', function(event) {
            var $this = $(this);
            var title = $this.attr('title');
            var popover = $('div.popover[data-dismissid="' + randomId + '"]');
            title = title === "" ? $this.attr('data-original-title') : title;

            if (title === "") {
                title = "&nbsp;";
                // adjust popover position (title was empty)
                var top = popover.offset().top;
                popover.css('top', (top-17) + 'px');
            }
            var popoverTitle = popover.find('h3.popover-title');
            popoverTitle.html(title + closeButtonHtml);
            if (callback !== undefined) {
                callback(popover);
            }
        })
        .on('keydown.volatilePopover', function(e) {
            if(e.keyCode == 27) { // ESC
                $(this).popover('destroy');
                $(this).off('keydown.volatilePopover');
            }
        });

        if (hover) {
            $clicked.on('mouseenter', function() {
                var _this = this;
                $clicked.popover('show');
                $(".popover").on("mouseleave", function() { // close popover when leaving it
                    $(_this).popover('hide');
                });
            })
            .on('mouseleave', function() { // close popover if button not hovered (timeout)
                var _this = this;
                setTimeout(function() {
                    if ($('.popover:hover').length == 0 && !$(_this).is(":hover")) {
                        $(_this).popover('hide');
                    }
                },
                300);
            });
        } else {
            $clicked.popover('show');
        }

    } else {
        // $clicked.popover('show');
    }
    var popover = $clicked.data('popover');

    if (data === undefined) {
        return popover
    } else if (popover.options.content !== data) {
        popover.options.content =  data;
        $clicked.popover('show');
        return popover;
    }
}

function getMatrixPopup(scope, scope_id, galaxy_id) {
    cancelPopoverForm();
    getPopup(scope_id + '/' + galaxy_id + '/' + scope, 'events', 'viewGalaxyMatrix', '', '#popover_matrix');
}

function getPopup(id, context, target, admin, popupType) {
    $("#gray_out").fadeIn();
    var url = "";
    if (typeof admin !== 'undefined' && admin != '') url+= "/admin";
    if (context != '') {
        url += "/" + context;
    }
    if (target != '') url += "/" + target;
    if (id != '') url += "/" + id;
    if (popupType == '' || typeof popupType == 'undefined') popupType = '#popover_form';
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        async: true,
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $(popupType).html(data);
            openPopup(popupType, false);
        },
        error:function(xhr) {
            $(".loading").hide();
            $("#gray_out").fadeOut();
            if (xhr.status === 403) {
                showMessage('fail', 'Not allowed.');
            } else {
                showMessage('fail', 'Something went wrong - the queried function returned an exception. Contact your administrator for further details (the exception has been logged).');
            }
        },
        url: url
    });
}

// Same as getPopup function but create a popover to populate first
function popoverPopup(clicked, id, context, target, admin) {
    var url = "";
    if (typeof admin !== 'undefined' && admin != '') url+= "/admin";
    if (context != '') {
        url += "/" + context;
    }
    if (target != '') url += "/" + target;
    if (id != '') url += "/" + id;
    var popover = openPopover(clicked, undefined);
    $clicked = $(clicked);

    // actual request //
    $.ajax({
        dataType:"html",
        async: true,
        cache: false,
        success:function (data, textStatus) {
            if (popover.options.content !== data) {
                popover.options.content =  data;
                $clicked.popover('show');
            }
        },
        error:function() {
            popover.options.content =  '<div class="alert alert-error" style="margin-bottom: 0px;">Something went wrong - the queried function returned an exception. Contact your administrator for further details (the exception has been logged).</div>';
            $clicked.popover('show');
        },
        url: url
    });
}

// create a confirm popover on the clicked html node.
function popoverConfirm(clicked) {
    var $clicked = $(clicked);
    var popoverContent = '<div>';
        popoverContent += '<button id="popoverConfirmOK" class="btn btn-primary" onclick=submitPopover(this)>Yes</button>';
        popoverContent += '<button class="btn btn-inverse" style="float: right;" onclick=cancelPrompt()>Cancel</button>';
    popoverContent += '</div>';
    openPopover($clicked, popoverContent);
    $("#popoverConfirmOK")
    .focus()
    .bind("keydown", function(e) {
        if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
            $(this).click();
        }
        if(e.keyCode == 27) { // ESC
            $clicked.popover('destroy');
        }
    });
}

function submitPopover(clicked) {
    var $clicked = $(clicked);
    var $form = $clicked.closest('form');
    if ($form.length === 0) { // popover container is body, submit from original node
        var dismissid = $clicked.closest('div.popover').attr('data-dismissid');
        $form = $('[data-dismissid="' + dismissid + '"]').closest('form');
    }
    $form.submit();
}

function simplePopup(url) {
    $("#gray_out").fadeIn();
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        async: true,
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $("#popover_form").html(data);
            openPopup("#popover_form");
        },
        error:function(xhr) {
            $(".loading").hide();
            $("#gray_out").fadeOut();
            if (xhr.status == 403) {
                showMessage('fail', 'Not allowed.');
            } else if (xhr.status == 404) {
                showMessage('fail', 'Resource not found.');
            } else {
                showMessage('fail', 'Something went wrong - the queried function returned an exception. Contact your administrator for further details (the exception has been logged).');
            }
        },
        url: url,
    });
}

function choicePopup(legend, list) {
    var popupHtml = '<div class="popover_choice">';
    popupHtml += '<legend>Select Object Category</legend>';
        popupHtml += '<div class="popover_choice_main" id ="popover_choice_main">';
            popupHtml += '<table style="width:100%;" id="MainTable">';
                popupHtml += '<tbody>';
                    list.forEach(function(item) {
                        popupHtml += '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">';
                            popupHtml += '<td role="button" tabindex="0" aria-label="All meta-categories" title="'+item.text+'" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="'+item.onclick+';">'+item.text+'</td>';
                        popupHtml += '</tr>';
                    });
                popupHtml += '</tbody>';
            popupHtml += '</table>';
        popupHtml += '</div>';
        popupHtml += '<div role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>';
    popupHtml += '</div>';

    $("#popover_form").html(popupHtml);
    openPopup("#popover_form");
}

function openModal(heading, body, footer, modal_option, css_container, css_body) {
    var modal_id = 'dynamic_modal_' + new Date().getTime();
    var modal_html = '<div id="' + modal_id + '" class="modal hide fade" style="' + (css_container !== undefined ? css_container : '') + '" tabindex="-1" role="dialog" aria-hidden="true">';
    if (heading !== undefined && heading !== '') {
        modal_html += '<div class="modal-header">'
                        + '<button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>'
                        + '<h3 id="myModalLabel">' + heading + '</h3>'
                    + '</div>';
    }
    if (body !== undefined && body !== '') {
        modal_html += '<div class="modal-body" style="' + (css_body !== undefined ? css_body : '') + '">' + body + '</div>';
    }
    if (footer !== undefined && footer !== '') {
        modal_html += '<div class="modal-footer">' + footer + '</div>';
    }
    modal_html += '</div>';
    $('body').append($(modal_html));
    $('#'+modal_id).modal(modal_option !== undefined ? modal_option : {});
}

function resizePopoverBody() {
    var bodyheight = $(window).height();
    bodyheight = 3 * bodyheight / 4 - 150;
    $("#popover_choice_main").css({"max-height": bodyheight});
}

function populateTemplateHiddenFileDiv(files) {
    $('#TemplateFileArray').val(JSON.stringify(files));
}

function populateTemplateFileBubbles() {
    var fileObjectArray = JSON.parse($('#TemplateFileArray').val());
    fileObjectArray.forEach(function(entry) {
        templateAddFileBubble(entry.element_id, false, entry.filename, entry.tmp_name, 'yes');
    });
}

function templateFileHiddenAdd(files, element_id, batch) {
    var fileArray = $.parseJSON($('#TemplateFileArray', window.parent.document).val());
    var contained = false;
    for (var j=0; j< files.length; j++) {
        for (var i=0; i< fileArray.length; i++) {
            if (fileArray[i].filename == files[j].filename) {
                contained = true;
            }
            if (batch == 'no' && fileArray[i].element_id == element_id) {
                templateDeleteFileBubble(fileArray[i].filename, fileArray[i].tmp_name, fileArray[i].element_id, 'iframe', batch);
                contained = false;
                var removeId = i;
            }
        }
        if (batch == 'no') fileArray.splice(removeId, 1);
        if (contained == false) {
            fileArray.push(files[j]);
            templateAddFileBubble(element_id, true, files[j].filename, files[j].tmp_name, batch);
            $('#TemplateFileArray', window.parent.document).val(JSON.stringify(fileArray));
        }
    }
}

function htmlEncode(value){
    return $('<div/>').text(value).html();
}

function templateAddFileBubble(element_id, iframe, filename, tmp_name, batch) {
    filename = htmlEncode(filename);
    tmp_name = htmlEncode(tmp_name);
    if (batch == 'no') {
        if (iframe == true) {
            $('#filenames_' + element_id, window.parent.document).html('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'no\');" class="tagSecondHalf useCursorPointer">x</span></div>');
        } else {
            $('#filenames_' + element_id).html('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'no\');" class="tagSecondHalf useCursorPointer">x</span></div>');
        }
    } else {
        if (iframe == true) {
            $('#filenames_' + element_id, window.parent.document).append('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'yes\');" class="tagSecondHalf useCursorPointer">x</span></div>');
        } else {
            $('#filenames_' + element_id).append('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'yes\');" class="tagSecondHalf useCursorPointer">x</span></div>');
        }
    }
}

function templateDeleteFileBubble(filename, tmp_name, element_id, context, batch) {
    $(".loading").show();
    $.ajax({
        type:"post",
        cache: false,
        url:"/templates/deleteTemporaryFile/" + tmp_name,
    });
    var c = this;
    if (context == 'iframe') {
        $('#' + tmp_name + '_container', window.parent.document).remove();
        var oldArray = JSON.parse($('#TemplateFileArray', window.parent.document).val());
    } else {
        $('#' + tmp_name + '_container').remove();
        var oldArray = JSON.parse($('#TemplateFileArray').val());
    }
    var newArray = [];
    oldArray.forEach(function(entry) {
        if (batch == 'no') {
            if (entry.element_id != element_id) {
                newArray.push(entry);
            }
        } else {
            if (entry.tmp_name != tmp_name) {
                newArray.push(entry);
            }
        }
    });
    if (batch == 'no') {
        $('#fileUploadButton_' + element_id, $('#iframe_' + element_id).contents()).html('Upload File');
    }
    if (context == 'iframe') {
        $('#TemplateFileArray', window.parent.document).val(JSON.stringify(newArray));
    } else {
        $('#TemplateFileArray').val(JSON.stringify(newArray));
    }
    $(".loading").hide();
}

function templateFileUploadTriggerBrowse(id) {
    $('#upload_' + id + '_file').click();
}

function freetextRemoveRow(id, event_id) {
    $('#row_' + id).hide();
    $('#Attribute' + id + 'Save').attr("value", "0");
    if ($(".freetext_row:visible").length == 0) {
        window.location = "/events/" + event_id;
    }
}

function indexEvaluateFiltering() {
    if (filterContext == "event") {
        if (filtering.published != 2) {
            $('#value_published').html(publishedOptions[filtering.published]);
        } else {
            $('#value_published').html("");
        }
        if (filtering.hasproposal != 2) {
            $('#value_hasproposal').html(publishedOptions[filtering.hasproposal]);
        } else {
            $('#value_hasproposal').html("");
        }
        if (filtering.date.from != null) {
            var text = "";
            if (filtering.date.from != "") text = "From: " + $('<span>').text(filtering.date.from).html();
            if (filtering.date.until != "") {
                if (text != "") text += " ";
                text += "Until: " + $('<span>').text(filtering.date.until).html();
            }
        }
        $('#value_date').html(text);
        for (var i = 0; i < simpleFilters.length; i++) {
            indexEvaluateSimpleFiltering(simpleFilters[i]);
        }
        indexRuleChange();
    } else {
        for (var i = 0; i < differentFilters.length; i++) {
            if (filtering[differentFilters[i]] != "") {
                var text = "";
                if (filtering[differentFilters[i]] == 1) text = "Yes";
                else if (filtering[differentFilters[i]] == 0) text = "No";
                $('#value_' + differentFilters[i]).text(text);
            } else {
                $('#value_' + differentFilters[i]).text("");
            }
        }
        for (var i = 0; i < simpleFilters.length; i++) {
            indexEvaluateSimpleFiltering(simpleFilters[i]);
        }
    }
    indexSetTableVisibility();
    indexSetRowVisibility();
    $('#generatedURLContent').text(indexCreateFilters());
}

function quickFilter(passedArgs, url) {
    if(!passedArgs){
        var passedArgs = [];
    }
    if( $('#quickFilterField').val().trim().length > 0){
        passedArgs["searchall"] = $('#quickFilterField').val().trim();
        for (var key in passedArgs) {
            if (key !== 'page') {
                url += "/" + key + ":" + passedArgs[key];
            }
        }
    }
    window.location.href=url;
}

function runIndexFilter(element) {
    var dataFields = $(element).data();
    for (var k in $(element).data()) {
        if (k in passedArgsArray) {
            delete(passedArgsArray[k]);
        } else {
            passedArgsArray[k] = dataFields[k];
        }
    }
    url = here;
    for (var key in passedArgsArray) {
        url += "/" + key + ":" + passedArgsArray[key];
    }
    window.location.href = url;
}

function runIndexQuickFilter(preserveParams) {
    if (!passedArgsArray) {
        var passedArgsArray = [];
    }
    var searchKey = 'searchall';
    if ($('#quickFilterField').data('searchkey')) {
        searchKey = $('#quickFilterField').data('searchkey');
    }
    if ( $('#quickFilterField').val().trim().length > 0){
        passedArgsArray[searchKey] = $('#quickFilterField').val().trim();
    }
    url = here;
    if (typeof preserveParams !== "undefined") {
        url += preserveParams;
    }
    for (var key in passedArgsArray) {
        if (key !== 'page') {
            url += "/" + key + ":" + passedArgsArray[key];
        }
    }
    window.location.href = url;
}

function executeFilter(passedArgs, url) {
    for (var key in passedArgs) url += "/" + key + ":" + passedArgs[key];
    window.location.href=url;
}

function quickFilterTaxonomy(taxonomy_id, passedArgs) {
    var url = "/taxonomies/view/" + taxonomy_id + "/filter:" + $('#quickFilterField').val();
    window.location.href=url;
}

function quickFilterRemoteEvents(passedArgs, id) {
    passedArgs["searchall"] = $('#quickFilterField').val();
    var url = "/servers/previewIndex/" + id;
    for (var key in passedArgs) {
        url += "/" + key + ":" + passedArgs[key];
    }
    window.location.href=url;
}

function remoteIndexApplyFilters() {
    var url = actionUrl + '/' + $("#EventFilter").val();
    window.location.href = url;
}

function indexApplyFilters() {
    var url = indexCreateFilters();
    window.location.href = url;
}

function indexCreateFilters() {
    text = "";
    if (filterContext == 'event') {
        if (filtering.published != "2") {
            text += "searchpublished:" + filtering.published;
        }
        if (filtering.hasproposal != "2") {
            if (text != "") text += "/";
            text += "searchhasproposal:" + filtering.hasproposal;
        }
    } else {
        for (var i = 0; i < differentFilters.length; i++) {
            if (filtering[differentFilters[i]]) {
                if (text != "") text += "/";
                text += "search" + differentFilters[i] + ":" + filtering[differentFilters[i]];
            }
        }
    }
    for (var i = 0; i < simpleFilters.length; i++) {
        text = indexBuildArray(simpleFilters[i], text);
    }
    if (filterContext == 'event') {
        if (filtering.date.from) {
            if (text != "") text += "/";
            text += "searchDatefrom:" + filtering.date.from;
        }
        if (filtering.date.until) {
            if (text != "") text += "/";
            text += "searchDateuntil:" + filtering.date.until;
        }
        return baseurl + '/events/index/' + text;
    } else {
        return baseurl + '/admin/users/index/' + text;
    }
}

function indexBuildArray(type, text) {
    temp = "";
    if (text != "") temp += "/";
    temp += "search" + type + ":";
    if (filtering[type].NOT.length == 0 && filtering[type].OR.length == 0) return text;
    var swap = filtering[type].OR.length;
    var temp_array = filtering[type].OR.concat(filtering[type].NOT);
    for (var i = 0; i < temp_array.length; i++) {
        if (i > 0) temp += "|";
        if (i >= swap) temp +="!";
        temp += temp_array[i];
    }
    text += temp;
    return text;
}

function indexSetRowVisibility() {
    for (var i = 0; i < allFields.length; i++) {
        if ($("#value_" + allFields[i]).text().trim() != "") {
            $("#row_" + allFields[i]).show();
        } else {
            $("#row_" + allFields[i]).hide();
        }
    }
}

function indexEvaluateSimpleFiltering(field) {
    text = "";
    if (filtering[field].OR.length == 0 && filtering[field].NOT.length == 0) {
        $('#value_' + field).html(text);
        return false;
    }
    if (filtering[field].OR.length !=0) {
        for (var i = 0; i < filtering[field].OR.length; i++) {
            if (i > 0) text += '<span class="green bold"> OR </span>';
            if (typedFields.indexOf(field) == -1) {
                text += $('<span>').text(filtering[field].OR[i]).html();
            } else {
                for (var j = 0; j < typeArray[field].length; j++) {
                    if (typeArray[field][j].id == filtering[field].OR[i]) {
                        text += $('<span>').text(typeArray[field][j].value).html();
                    }
                }
            }
        }
    }
    if (filtering[field].NOT.length !=0) {
        for (var i = 0; i < filtering[field].NOT.length; i++) {
            if (i == 0) {
                if (text != "") text += '<span class="red bold"> AND NOT </span>';
                else text += '<span class="red bold">NOT </span>';
            } else text += '<span class="red bold"> AND NOT </span>';
            if (typedFields.indexOf(field) == -1) {
                text += $('<span>').text(filtering[field].NOT[i]).html();
            } else {
                for (var j = 0; j < typeArray[field].length; j++) {
                    if (typeArray[field][j].id == filtering[field].NOT[i]) {
                        text += $('<span>').text(typeArray[field][j].value).html();
                    }
                }
            }
        }
    }
    $('#value_' + field).html(text);
}

function indexAddRule(param) {
    var found = false;
    if (filterContext == 'event') {
        if (param.data.param1 == "date") {
            var val1 = escape($('#EventSearch' + param.data.param1 + 'from').val());
            var val2 = escape($('#EventSearch' + param.data.param1 + 'until').val());
            if (val1 != "") filtering.date.from = val1;
            if (val2 != "") filtering.date.until = val2;
        } else if (param.data.param1 == "published") {
            var value = escape($('#EventSearchpublished').val());
            if (value != "") filtering.published = value;
        } else if (param.data.param1 == "hasproposal") {
            var value = escape($('#EventSearchhasproposal').val());
            if (value != "") filtering.hasproposal = value;
        } else {
            var value = escape($('#EventSearch' + param.data.param1).val());
            var operator = operators[escape($('#EventSearchbool').val())];
            if (value != "" && filtering[param.data.param1][operator].indexOf(value) < 0) filtering[param.data.param1][operator].push(value);
        }
    } else if (filterContext == 'user') {
        if (differentFilters.indexOf(param.data.param1) != -1) {
            var value = escape($('#UserSearch' + param.data.param1).val());
            if (value != "") filtering[param.data.param1] = value;
        } else {
            var value = escape($('#UserSearch' + param.data.param1).val());
            var operator = operators[escape($('#UserSearchbool').val())];
            if (value != "" && filtering[param.data.param1][operator].indexOf(value) < 0) filtering[param.data.param1][operator].push(value);
        }
    }
    indexEvaluateFiltering();
}

function indexSetTableVisibility() {
    var visible = false;
    if ($("[id^='value_']").text().trim()!="" && $("[id^='value_']").text().trim()!="-1") {
        visible = true;
    }
    if (visible == true) $('#FilterplaceholderTable').hide();
    else $('#FilterplaceholderTable').show();
}

function indexRuleChange() {
    var context = filterContext.charAt(0).toUpperCase() + filterContext.slice(1);
    $('[id^=' + context + 'Search]').hide();
    var rule = $('#' + context + 'Rule').val();
    var fieldName = '#' + context + 'Search' + rule;
    if (fieldName == '#' + context + 'Searchdate') {
        $(fieldName + 'from').show();
        $(fieldName + 'until').show();
    } else {
        $(fieldName).show();
    }
    if (simpleFilters.indexOf(rule) != -1) {
        $('#' + context + 'Searchbool').show();
    } else $('#' + context + 'Searchbool').hide();

    $('#addRuleButton').show();
    $('#addRuleButton').unbind("click");
    $('#addRuleButton').click({param1: rule}, indexAddRule);
}

function indexFilterClearRow(field) {
    $('#value_' + field).html("");
    $('#row_' + field).hide();
    if (field == "date") {
        filtering.date.from = "";
        filtering.date.until = "";
    } else if (field == "published") {
        filtering.published = 2;
    } else if (field == "hasproposal") {
        filtering.hasproposal = 2;
    } else if (differentFilters.indexOf(field) != -1) {
        filtering[field] = "";
    } else {
        filtering[field].NOT = [];
        filtering[field].OR = [];
    }
    indexSetTableVisibility();
    indexEvaluateFiltering();
}


function restrictEventViewPagination() {
    var showPages = new Array();
    var start;
    var end;
    var i;

    if (page < 6) {
        start = 1;
        if (count - page < 6) {
            end = count;
        } else {
            end = page + (9 - (page - start));
        }
    } else if (count - page < 6) {
        end = count;
        start = count - 10;
    } else {
        start = page-5;
        end = page+5;
    }

    if (start > 2) {
        $("#apage" + start).parent().before("<li><a href id='aExpandLeft'>...</a></li>");
        $("#aExpandLeft").click(function() {expandPagination(0, 0); return false;});
        $("#bpage" + start).parent().before("<li><a href id='bExpandLeft'>...</a></li>");
        $("#bExpandLeft").click(function() {expandPagination(1, 0); return false;})
    }

    if (end < (count - 1)) {
        $("#apage" + end).parent().after("<li><a href id='aExpandRight'>...</a></li>");
        $("#aExpandRight").click(function() {expandPagination(0, 1); return false;});
        $("#bpage" + end).parent().after("<li><a href id='bExpandRight'>...</a></li>");
        $("#bExpandRight").click(function() {expandPagination(1, 1); return false;})
    }

    for (i = 1; i < (count+1); i++) {
        if (i != 1 && i != count && (i < start || i > end)) {
            $("#apage" + i).hide();
            $("#bpage" + i).hide();
        }
    }
}

function expandPagination(bottom, right) {
    var i;
    var prefix = "a";
    if (bottom == 1) prefix = "b";
    var start = 1;
    var end = page;
    if (right == 1) {
        start = page;
        end = count;
        $("#" + prefix + "ExpandRight").remove();
    } else $("#" + prefix + "ExpandLeft").remove();
    for (i = start; i < end; i++) {
        $("#" + prefix + "page" + i).show();
    }
}

function getSubGroupFromSetting(setting) {
    var temp = setting.split('.');
    if (temp[0] == "Plugin") {
        temp = temp[1];
        if (temp.indexOf('_') > -1) {
            temp = temp.split('_');
            return temp[0];
        }
    }
    return 'general';
}

function serverSettingsActivateField(setting, id) {
    resetForms();
    $('.inline-field-placeholder').hide();
    var fieldName = "#setting_" + getSubGroupFromSetting(setting) + "_" + id;
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $(fieldName + "_placeholder").html(data);
            $(fieldName + "_solid").hide();
            $(fieldName + "_placeholder").show();
            serverSettingsPostActivationScripts(fieldName, setting, id);
        },
        url:"/servers/serverSettingsEdit/" + setting + "/" + id,
    });
}

function serverSettingsPostActivationScripts(name, setting, id) {
    $(name + '_field').focus();
    inputFieldButtonActive(name + '_field');

    $(name + '_form').submit(function(e){
        e.preventDefault();
        serverSettingSubmitForm(name, setting, id);
        return false;
    });

    $(name + '_form').bind("focusout", function() {
        inputFieldButtonPassive(name + '_field');
    });

    $(name + '_form').bind("focusin", function(){
        inputFieldButtonActive(name + '_field');
    });

    $(name + '_form').bind("keydown", function(e) {
        if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
            serverSettingSubmitForm(name, setting, id);
        }
    });
    $(name + '_field').closest('.inline-input-container').children('.inline-input-accept').bind('click', function() {
        serverSettingSubmitForm(name, setting, id);
    });
    $(name + '_field').closest('.inline-input-container').children('.inline-input-decline').bind('click', function() {
        resetForms();
        $('.inline-field-placeholder').hide();
    });

    $(name + '_solid').hide();
}

function serverSettingSubmitForm(name, setting, id) {
    subGroup = getSubGroupFromSetting(setting);
    var formData = $(name + '_field').closest("form").serialize();
    $.ajax({
        data: formData,
        cache: false,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            $.ajax({
                type:"get",
                url:"/servers/serverSettingsReloadSetting/" + setting + "/" + id,
                success:function (data2, textStatus2) {
                    $('#' + subGroup + "_" + id + '_row').replaceWith(data2);
                    $(".loading").hide();
                },
                error:function() {
                    showMessage('fail', 'Could not refresh the table.');
                }
            });
        },
        error:function() {
            showMessage('fail', 'Request failed for an unknown reason.');
            resetForms();
            $('.inline-field-placeholder').hide();
        },
        type:"post",
        url:"/servers/serverSettingsEdit/" + setting + "/" + id + "/" + 1
    });
    $(name + '_field').unbind("keyup");
    $(name + '_form').unbind("focusout");
    return false;
}

function updateOrgCreateImageField(string) {
    string = escape(string);
    $.ajax({
        url:'/img/orgs/' + string + '.png',
        type:'HEAD',
        error:
            function(){
                $('#logoDiv').html('No image uploaded for this identifier');
            },
        success:
            function(){
                $('#logoDiv').html('<img src="/img/orgs/' + string + '.png" style="width:24px;height:24px;"></img>');
            }
    });
}

function generateOrgUUID() {
    $.ajax({
        url:'/admin/organisations/generateuuid.json',
        success:
            function( data ){
                $('#OrganisationUuid').val(data.uuid);
            }
    });
}


function sharingGroupIndexMembersCollapse(id) {
    $('#' + id + '_down').show();
    $('#' + id + '_up').hide();
}

function sharingGroupIndexMembersExpand(id) {
    $('#' + id + '_down').hide();
    $('#' + id + '_up').show();
}

function popoverStartup() {
    $('[data-toggle="popover"]').popover({
        animation: true,
        html: true,
    }).click(function(e) {
        $(e.target).popover('show');
        $('[data-toggle="popover"]').not(e.target).popover('hide');
    });
    $(document).click(function (e) {
        if (!$('[data-toggle="popover"]').is(e.target)) {
            $('[data-toggle="popover"]').popover('hide');
        }
    });
}

function changeFreetextImportFrom() {
    $('#changeTo').find('option').remove();
    options[$('#changeFrom').val()].forEach(function(element) {
        $('#changeTo').append('<option value="' + element + '">' + element + '</option>');
    });
}

function changeFreetextImportCommentExecute() {
    $('.freetextCommentField').val($('#changeComments').val());
}

function changeFreetextImportExecute() {
    var from = $('#changeFrom').val();
    var to = $('#changeTo').val();
    $('.typeToggle').each(function() {
        if ($( this ).val() == from) {
            if (selectContainsOption("#" + $(this).attr('id'), to)) $( this ).val(to);
        }
    });
}

function selectContainsOption(selectid, value) {
    var exists = false;
    $(selectid + ' option').each(function(){
        if (this.value == value) {
            exists = true;
            return false;
        }
    });
    return exists;
}

function exportChoiceSelect(e) {
    if ($(e.target).is("input")) {
        return false;
    }
    var url = $(e.target).parent().data("export-url");
    var elementId = $(e.target).parent().data("export-key");
    var checkbox = $(e.target).parent().data("export-checkbox");
    if (checkbox == 1) {
        if ($('#' + elementId + '_toggle').prop('checked')) {
            url = $('#' + elementId + '_set').html();
        }
    }
    document.location.href = url;
}

function importChoiceSelect(url, elementId, ajax) {
    if (ajax == 'false') {
        document.location.href = url;
    } else {
        simplePopup(url);
    }
}

function freetextImportResultsSubmit(id, count) {
    var attributeArray = [];
    var temp;
    for (i = 0; i < count; i++) {
        if ($('#Attribute' + i + 'Save').val() == 1) {
            temp = {
                value:$('#Attribute' + i + 'Value').val(),
                category:$('#Attribute' + i + 'Category').val(),
                type:$('#Attribute' + i + 'Type').val(),
                to_ids:$('#Attribute' + i + 'To_ids')[0].checked,
                disable_correlation:$('#Attribute' + i + 'Disable_correlation')[0].checked,
                comment:$('#Attribute' + i + 'Comment').val(),
                distribution:$('#Attribute' + i + 'Distribution').val(),
                sharing_group_id:$('#Attribute' + i + 'SharingGroupId').val(),
                data:$('#Attribute' + i + 'Data').val(),
                data_is_handled:$('#Attribute' + i + 'DataIsHandled').val(),
                tags:$('#Attribute' + i + 'Tags').val()
            }
            attributeArray[attributeArray.length] = temp;
        }
    };
    $("#AttributeJsonObject").val(JSON.stringify(attributeArray));
    var formData = $(".mainForm").serialize();
    $.ajax({
        type: "post",
        cache: false,
        url: "/events/saveFreeText/" + id,
        data: formData,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            window.location = '/events/view/' + id;
        },
        complete:function() {
            $(".loading").hide();
        },
    });
}

function moduleResultsSubmit(id) {
    var typesWithData = ['attachment', 'malware-sample'];
    var data_collected = {};
    var temp;
    if ($('.meta_table').length) {
        var tags = [];
        $('.meta_table').find('.tag').each(function() {
            tags.push({name: $(this).text()});
        });
        if (tags.length) {
            data_collected['Tag'] = tags;
        }
    }
    if ($('.MISPObject').length) {
        var objects = [];
        $(".MISPObject").each(function(o) {
            var object_uuid = $(this).find('.ObjectUUID').text();
            temp = {
                uuid: object_uuid,
                name: $(this).find('.ObjectName').text(),
                meta_category: $(this).find('.ObjectMetaCategory').text(),
                distribution: $(this).find('.ObjectDistribution').val(),
                sharing_group_id: $(this).find('.ObjectSharingGroup').val(),
                comment: $(this).find('.ObjectComment').val()
            }
            if (temp['distribution'] != '4') {
                temp['sharing_group_id'] = '0';
            }
            if ($(this).has('.ObjectID').length) {
                temp['id'] = $(this).find('.ObjectID').text();
            }
            if ($(this).has('.ObjectDescription').length) {
                temp['description'] = $(this).find('.ObjectDescription').text();
            }
            if ($(this).has('.TemplateVersion').length) {
                temp['template_version'] = $(this).find('.TemplateVersion').text();
            }
            if ($(this).has('.TemplateUUID').length) {
                temp['template_uuid'] = $(this).find('.TemplateUUID').text();
            }
            if ($(this).has('.ObjectReference').length) {
                var references = [];
                $(this).find('.ObjectReference').each(function() {
                    var reference = {
                        object_uuid: object_uuid,
                        referenced_uuid: $(this).find('.ReferencedUUID').text(),
                        relationship_type: $(this).find('.Relationship').text()
                    };
                    references.push(reference);
                });
                temp['ObjectReference'] = references;
            }
            if ($(this).find('.ObjectAttribute').length) {
                var object_attributes = [];
                $(this).find('.ObjectAttribute').each(function(a) {
                    var attribute_type = $(this).find('.AttributeType').text();
                    attribute = {
                        object_relation: $(this).find('.ObjectRelation').text(),
                        category: $(this).find('.AttributeCategory').text(),
                        type: attribute_type,
                        value: $(this).find('.AttributeValue').text(),
                        uuid: $(this).find('.AttributeUuid').text(),
                        to_ids: $(this).find('.AttributeToIds')[0].checked,
                        disable_correlation: $(this).find('.AttributeDisableCorrelation')[0].checked,
                        comment: $(this).find('.AttributeComment').val(),
                        distribution: $(this).find('.AttributeDistribution').val(),
                        sharing_group_id: $(this).find('.AttributeSharingGroup').val()
                    }
                    if (attribute['distribution'] != '4') {
                        attribute['sharing_group_id'] = '0';
                    }
                    if ($(this).find('.objectAttributeTagContainer').length) {
                        var tags = [];
                        $(this).find('.objectAttributeTag').each(function() {
                            tags.push({name: $(this).attr('title')});
                        });
                        attribute['Tag'] = tags;
                    }
                    if (typesWithData.indexOf(attribute_type) != -1) {
                        if ($(this).find('.AttributeData').length) {
                            attribute['data'] = $(this).find('.AttributeData').val();
                        }
                        if ($(this).find('.AttributeEncrypt').length) {
                            attribute['encrypt'] = $(this).find('.AttributeEncrypt').val();
                        }
                    }
                    object_attributes.push(attribute);
                });
                temp['Attribute'] = object_attributes;
            }
            objects.push(temp);
        });
        data_collected['Object'] = objects;
    }
    if ($('.MISPAttribute').length) {
        var attributes = [];
        $('.MISPAttribute').each(function(a) {
            var category_value;
            var type_value;
            if ($(this).find('.AttributeCategorySelect').length) {
                category_value = $(this).find('.AttributeCategorySelect').val();
            } else {
                category_value = $(this).find('.AttributeCategory').text();
            }
            if ($(this).find('.AttributeTypeSelect').length) {
                type_value = $(this).find('.AttributeTypeSelect').val();
            } else {
                type_value = $(this).find('.AttributeType').text();
            }
            temp = {
                category: category_value,
                type: type_value,
                value: $(this).find('.AttributeValue').text(),
                uuid: $(this).find('.AttributeUuid').text(),
                to_ids: $(this).find('.AttributeToIds')[0].checked,
                disable_correlation: $(this).find('.AttributeDisableCorrelation')[0].checked,
                comment: $(this).find('.AttributeComment').val(),
                distribution: $(this).find('.AttributeDistribution').val(),
                sharing_group_id: $(this).find('.AttributeSharingGroup').val()
            }
            if (temp['distribution'] != '4') {
                temp['sharing_group_id'] = '0';
            }
            if ($(this).find('.attributeTagContainer').length) {
                var tags = [];
                $(this).find('.attributeTag').each(function() {
                    tags.push({name: $(this).attr('title')});
                });
                temp['Tag'] = tags;
            }
            if (typesWithData.indexOf(type_value) != -1) {
                if ($(this).find('.AttributeData').length) {
                    temp['data'] = $(this).find('.AttributeData').val();
                }
                if ($(this).find('.AttributeEncrypt').length) {
                    temp['encrypt'] = $(this).find('.AttributeEncrypt').val();
                }
            }
            attributes.push(temp);
        });
        data_collected['Attribute'] = attributes;
    }
    $("#EventJsonObject").val(JSON.stringify(data_collected));
    var formData = $('.mainForm').serialize();
    $.ajax({
        type: "post",
        cache: false,
        url: "/events/handleModuleResults/" + id,
        data: formData,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            window.location = '/events/view/' + id;
        },
        complete:function() {
            $(".loading").hide();
        }
    });
}

function objectTemplateViewContent(context, id) {
    var url = "/objectTemplateElements/viewElements/" + id + "/" + context;
    $.ajax({
            url: url,
            type:'GET',
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
            error: function(){
                $('#ajaxContent').html('An error has occured, please reload the page.');
            },
            success: function(response){
                $('#ajaxContent').html(response);
            },
        complete: function() {
            $(".loading").hide();
        },
    });

}

function organisationViewContent(context, id) {
    organisationViewButtonHighlight(context);
    var action = "/organisations/landingpage/";
    if (context == 'members') {
        action = "/admin/users/index/searchorg:";
    }
    if (context == 'events') {
        action = "/events/index/searchorg:";
    }
    $.ajax({
        url: action + id,
        type:'GET',
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        error: function(){
            $('#ajaxContent').html('An error has occured, please reload the page.');
        },
        success: function(response){
            $('#ajaxContent').html(response);
        },
        complete: function() {
            $(".loading").hide();
        },
    });
}

function organisationViewButtonHighlight(context) {
    $(".orgViewButtonActive").hide();
    $(".orgViewButton").show();
    $("#button_" + context).hide();
    $("#button_" + context + "_active").show();
}

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
    organisations.forEach(function(organisation){
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
    servers.forEach(function(server){
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
    organisations.forEach(function(org) {
        html = '<tr id="orgRow' + id + '" class="orgRow">';
        html += '<td class="short">' + org.type + '&nbsp;</td>';
        html += '<td>' + $('<div>').text(org.name).html() + '&nbsp;</td>';
        html += '<td>' + org.uuid + '&nbsp;</td>';
        html += '<td class="short" style="text-align:center;">';
        if (org.removable == 1) {
            html += '<input id="orgExtend' + id + '" type="checkbox" onClick="sharingGroupExtendOrg(' + id + ')" ';
            if (org.extend) html+= 'checked';
            html += '></input>';
        } else {
            html += '<span class="icon-ok"></span>'
        }
        html +='</td>';
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
    servers.forEach(function(server) {
        html = '<tr id="serverRow' + id + '" class="serverRow">';
        html += '<td>' + server.name + '&nbsp;</td>';
        html += '<td>' + server.url + '&nbsp;</td>';
        html += '<td>';
        html += '<input id="serverAddOrgs' + id + '" type="checkbox" onClick="sharingGroupServerAddOrgs(' + id + ')" ';
        if (server.all_orgs) html += 'checked';
        html += '></input>';
        html +='</td>';
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
        url = '/organisations/fetchOrgsForSG/' + jsonids + '/' + type
    } else if (context == 'server') {
        var jsonids = JSON.stringify(serverids);
        url = '/servers/fetchServersForSG/' + jsonids
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

function serverSubmitForm(action) {
    var ajax = {};
    switch ($('#ServerOrganisationType').val()) {
    case '0':
        ajax = {
            'id': $('#ServerLocal').val()
        };
        break;
    case '1':
        ajax = {
            'id': $('#ServerExternal').val()
        };
        break;
    case '2':
        ajax = {
            'name': $('#ServerExternalName').val(),
            'uuid': $('#ServerExternalUuid').val()
        };
        break;
    }

    $('#ServerJson').val(JSON.stringify(ajax));
    var formName = "#Server" + action + "Form";
    $(formName).submit();
}

function serverOrgTypeChange() {
    $(".hiddenField").hide();
    switch ($('#ServerOrganisationType').val()) {
        case '0':
            $("#ServerLocalContainer").show();
            break;
        case '1':
            $("#ServerExternalContainer").show();
            break;
        case '2':
            $("#ServerExternalUuidContainer").show();
            $("#ServerExternalNameContainer").show();
            break;
    }
}

function sharingGroupPopulateFromJson() {
    var jsonparsed = JSON.parse($('#SharingGroupJson').val());
    organisations = jsonparsed.organisations;
    servers = jsonparsed.servers;
    if (jsonparsed.sharingGroup.active == 1) {
        $("#SharingGroupActive").prop("checked", true);
    }
    if (jsonparsed.sharingGroup.roaming == 1) {
        $("#SharingGroupRoaming").prop("checked", true);
        $('#serverList').show();
    }
    $('#SharingGroupName').attr('value', jsonparsed.sharingGroup.name);
    $('#SharingGroupReleasability').attr('value', jsonparsed.sharingGroup.releasability);
    $('#SharingGroupDescription').text(jsonparsed.sharingGroup.description);
}

function testConnection(id) {
    $.ajax({
        url: '/servers/testConnection/' + id,
        type:'GET',
        beforeSend: function (XMLHttpRequest) {
            $("#connection_test_" + id).html('Running test...');
        },
        error: function(){
            $("#connection_test_" + id).html('Internal error.');
        },
        success: function(response){
            var result = response;
            switch (result.status) {
            case 1:
                status_message = "OK";
                compatibility = "Compatible";
                compatibility_colour = "green";
                colours = {'local': 'class="green"', 'remote': 'class="green"', 'status': 'class="green"'};
                issue_colour = "red";
                if (result.mismatch == "hotfix") issue_colour = "orange";
                if (result.newer == "local") {
                    colours.remote = 'class="' + issue_colour + '"';
                    if (result.mismatch == "minor") {
                        compatibility = "Pull only";
                        compatibility_colour = "orange";
                    } else if (result.mismatch == "major") {
                        compatibility = "Incompatible";
                        compatibility_colour = "red";
                    }
                } else if (result.newer == "remote") {
                    colours.local = 'class="' + issue_colour + '"';
                    if (result.mismatch != "hotfix") {
                        compatibility = "Incompatible";
                        compatibility_colour = "red";
                    }
                } else if (result.mismatch == "proposal") {
                    compatibility_colour = "orange";
                    compatibility = "Proposal pull disabled (remote version < v2.4.111)";
                }
                if (result.mismatch != false && result.mismatch != "proposal") {
                    if (result.newer == "remote") status_message = "Local instance outdated, update!";
                    else status_message = "Remote outdated, notify admin!"
                    colours.status = 'class="' + issue_colour + '"';
                }
                if (result.post != false) {
                    var post_colour = "red";
                    if (result.post == 1) {
                        post_colour = "green";
                        post_result = "Received sent package";
                    } else if (result.post == 8) {
                        post_result = "Could not POST message";
                    } else if (result.post == 9) {
                        post_result = "Invalid body";
                    } else if (result.post == 10) {
                        post_result = "Invalid headers";
                    } else {
                        post_colour = "orange";
                        post_result = "Remote too old for this test";
                    }
                }
                resultDiv = '<div>Local version: <span ' + colours.local + '>' + result.local_version + '</span><br />';
                resultDiv += '<div>Remote version: <span ' + colours.remote + '>' + result.version + '</span><br />';
                resultDiv += '<div>Status: <span ' + colours.status + '>' + status_message + '</span><br />';
                resultDiv += '<div>Compatiblity: <span class="' + compatibility_colour + '">' + compatibility + '</span><br />';
                resultDiv += '<div>POST test: <span class="' + post_colour + '">' + post_result + '</span><br />';
                $("#connection_test_" + id).html(resultDiv);
                //$("#connection_test_" + id).html('<span class="green bold" title="Connection established, correct response received.">OK</span>');
                break;
            case 2:
                $("#connection_test_" + id).html('<span class="red bold" title="There seems to be a connection issue. Make sure that the entered URL is correct and that the certificates are in order.">Server unreachable</span>');
                break;
            case 3:
                $("#connection_test_" + id).html('<span class="red bold" title="The server returned an unexpected result. Make sure that the provided URL (or certificate if it applies) are correct.">Unexpected error</span>');
                break;
            case 4:
                $("#connection_test_" + id).html('<span class="red bold" title="Authentication failed due to incorrect authentication key or insufficient privileges on the remote instance.">Authentication failed</span>');
                break;
            case 5:
                $("#connection_test_" + id).html('<span class="red bold" title="Authentication failed because the sync user is expected to change passwords. Log into the remote MISP to rectify this.">Password change required</span>');
                break;
            case 6:
                $("#connection_test_" + id).html('<span class="red bold" title="Authentication failed because the sync user on the remote has not accepted the terms of use. Log into the remote MISP to rectify this.">Terms not accepted</span>');
                break;
            case 7:
                $("#connection_test_" + id).html('<span class="red bold" title="The user account on the remote instance is not a sync user.">Remote user not a sync user</span>');
                break;
            }
        }
    })
}

function getTextColour(hex) {
    hex = hex.slice(1);
    var r = parseInt(hex.substring(0,2), 16);
    var g = parseInt(hex.substring(2,4), 16);
    var b = parseInt(hex.substring(4,6), 16);
    var avg = ((2 * r) + b + (3 * g))/6;
    if (avg < 128) {
        return 'white';
    } else {
        return 'black';
    }
}

function pgpChoiceSelect(uri) {
    $("#popover_form").fadeOut();
    $("#gray_out").fadeOut();
    $.ajax({
        type: "get",
        url: "https://pgp.circl.lu" + uri,
        success: function (data) {
            var result = data.split("<pre>")[1].split("</pre>")[0];
            $("#UserGpgkey").val(result);
            showMessage('success', "Key found!");
        },
        error: function (data, textStatus, errorThrown) {
            showMessage('fail', textStatus + ": " + errorThrown);
            $(".loading").hide();
            $("#gray_out").fadeOut();
        }
    });
}

function lookupPGPKey(emailFieldName) {
    simplePopup("/users/fetchPGPKey/" + $('#' + emailFieldName).val());
}

function zeroMQServerAction(action) {
    $.ajax({
        type: "get",
        url: "/servers/" + action + "ZeroMQServer/",
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success: function (data) {
            $(".loading").hide();
            if (action !== 'status') {
                window.location.reload();
            } else {
                $("#confirmation_box").html(data);
                openPopup("#confirmation_box");
            }
        },
        error: function (data, textStatus, errorThrown) {
            showMessage('fail', textStatus + ": " + errorThrown);
        }
    });
}

function convertServerFilterRules(rules) {
    validOptions.forEach(function (type) {
        container = "#"+ modelContext + type.ucfirst() + "Rules";
        if ($(container).val() != '' && $(container).val() != '[]') rules[type] = JSON.parse($(container).val());
        else {rules[type] = {"tags": {"OR": [], "NOT": []}, "orgs": {"OR": [], "NOT": []}}};
    });
    serverRuleUpdate();
    return rules;
}

function serverRuleUpdate() {
    var statusOptions = ["OR", "NOT"];
    validOptions.forEach(function(type) {
        validFields.forEach(function(field) {
            if (type === 'push') {
                var indexedList = {};
                window[field].forEach(function(item) {
                    indexedList[item.id] = item.name;
                });
            }
            statusOptions.forEach(function(status) {
                if (rules[type][field][status].length > 0) {
                    $('#' + type + '_' + field + '_' + status).show();
                    var t = '';
                    rules[type][field][status].forEach(function(item) {
                        if (t.length > 0) t += ', ';
                        if (type === 'pull') t += item;
                        else t += indexedList[item];
                    });
                    $('#' + type + '_' + field + '_' + status + '_text').text(t);
                } else {
                    $('#' + type + '_' + field + '_' + status).hide();
                }
            });
        });
    });
    serverRuleGenerateJSON();
}

function serverRuleFormActivate(type) {
    if (type != 'pull' && type != 'push') return false;
    $('.server_rule_popover').hide();
    $('#gray_out').fadeIn();
    $('#server_' + type + '_rule_popover').show();
}

function serverRuleCancel() {
    $("#gray_out").fadeOut();
    $(".server_rule_popover").fadeOut();
}

function serverRuleGenerateJSON() {
    validOptions.forEach(function(type) {
        if ($('#Server' + type.ucfirst() + "Rules").length) {
            $('#Server' + type.ucfirst() + "Rules").val(JSON.stringify(rules[type]));
        } else {
            $('#Feed' + type.ucfirst() + "Rules").val(JSON.stringify(rules[type]));
        }
    });
}

function serverRulePopulateTagPicklist() {
    var fields = ["tags", "orgs"];
    var target = "";
    fields.forEach(function(field) {
        target = "";
        window[field].forEach(function(element) {
            if ($.inArray(element.id, rules["push"][field]["OR"]) != -1) target = "#" + field + "pushLeftValues";
            else if ($.inArray(element.id, rules["push"][field]["NOT"]) != -1) target = "#" + field + "pushRightValues";
            else target = "#" + field + "pushMiddleValues";
            $(target).append($('<option/>', {
                value: element.id,
                text : element.name
            }));
        });
        target = "#" + field + "pullLeftValues";
        rules["pull"][field]["OR"].forEach(function(t) {
            $(target).append($('<option/>', {
                value: t,
                text : t
            }));
        });
        target = "#" + field + "pullRightValues";
        rules["pull"][field]["NOT"].forEach(function(t) {
            $(target).append($('<option/>', {
                value: t,
                text : t
            }));
        });
    });
}

function submitServerRulePopulateTagPicklistValues(context) {
    validFields.forEach(function(field) {
        rules[context][field]["OR"] = [];
        $("#" + field + context + "LeftValues option").each(function() {
            rules[context][field]["OR"].push($(this).val());
        });
        rules[context][field]["NOT"] = [];
        $("#" + field + context + "RightValues option").each(function() {
            rules[context][field]["NOT"].push($(this).val());
        });
    });

    $('#server_' + context + '_rule_popover').fadeOut();
    $('#gray_out').fadeOut();
    serverRuleUpdate();
}

// type = pull/push, field = tags/orgs, from = Left/Middle/Right, to = Left/Middle/Right
function serverRuleMoveFilter(type, field, from, to) {
    var opposites = {"Left": "Right", "Right": "Left"};
    // first fetch the value
    var value = "";
    if (type == "pull" && from == "Middle") {
        var doInsert = true;
        value = $("#" + field + type + "NewValue").val();
        if (value.length !== 0 && value.trim()) {
            $("#" + field + type + to + "Values" + " option").each(function() {
                if (value == $(this).val()) doInsert = false;
            });
            $("#" + field + type + opposites[to] + "Values" + " option").each(function() {
                if (value == $(this).val()) $(this).remove();
            });
            if (doInsert) {
                $("#" + field + type + to + "Values").append($('<option/>', {
                    value: value,
                    text : value
                }));
            }
        }
        $("#" + field + type + "NewValue").val('');
    } else {
        $("#" + field + type + from + "Values option:selected").each(function () {
            if (type != "pull" || to != "Middle") {
                value = $(this).val();
                text = $(this).text();
                $("#" + field + type + to + "Values").append($('<option/>', {
                    value: value,
                    text : text
                }));
            }
            $(this).remove();
        });
    }
}

function syncUserSelected() {
    if ($('#UserRoleId :selected').val() in syncRoles) {
        $('#syncServers').show();
    } else {
        $('#syncServers').hide();
    }
}

function filterAttributes(filter, id) {
    url = "/events/viewEventAttributes/" + id;
    if(filter === 'value'){
        filter = $('#quickFilterField').val().trim();
        url += filter.length > 0 ? "/searchFor:" + filter : "";
    } else if(filter !== 'all') {
        url += "/attributeFilter:" + filter
        filter = $('#quickFilterField').val().trim();
        url += filter.length > 0 ? "/searchFor:" + filter : "";
    }
    if (deleted) url += '/deleted:true';
    $.ajax({
        type:"get",
        url:url,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data) {
            $("#attributes_div").html(data);
            $(".loading").hide();
        },
        error:function() {
            showMessage('fail', 'Something went wrong - could not fetch attributes.');
        }
    });
}

function pivotObjectReferences(url, uuid) {
    url += '/focus:' + uuid;
    $.ajax({
        type:"get",
        url:url,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data) {
            $("#attributes_div").html(data);
            $(".loading").hide();
        },
        error:function() {
            showMessage('fail', 'Something went wrong - could not fetch attributes.');
        }
    });
}

function toggleBoolFilter(url, param) {
    if (querybuilderTool === undefined) {
        triggerEventFilteringTool(true); // allows to fetch rules
    }
    var rules = querybuilderTool.getRules({ skip_empty: true, allow_invalid: true });
    var res = cleanRules(rules);
    Object.keys(res).forEach(function(k) {
        if (url.indexOf(k) > -1) { // delete url rule (will be replaced by query builder value later on)
            var replace = '\/' + k + ".+/?";
            var re = new RegExp(replace,"i");
            url = url.replace(re, '');
        }
    });
    if (res[param] !== undefined) {
        if (param == 'deleted') {
            res[param] = res[param] == 0 ? 2 : 0;
        } else {
            res[param] = res[param] == 0 ? 1 : 0;
        }
    } else {
        if (param == 'deleted') {
            res[param] = 0;
        } else {
            res[param] = 1;
        }
    }

    url += buildFilterURL(res);
    url = url.replace(/view\//i, 'viewEventAttributes/');

    $.ajax({
        type:"get",
        url:url,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data) {
            $("#attributes_div").html(data);
            querybuilderTool = undefined;
            $(".loading").hide();
        },
        error:function() {
            showMessage('fail', 'Something went wrong - could not fetch attributes.');
        }
    });
}

function mergeOrganisationUpdate() {
    var orgTypeOptions = ['local', 'external'];
    var orgTypeSelects = ['OrganisationOrgsLocal', 'OrganisationOrgsExternal'];
    var orgTypeId = $('#OrganisationTargetType').val();
    var orgType = orgTypeSelects[orgTypeId];
    var orgID = $('#' + orgTypeSelects[orgTypeId]).val();
    console.log(orgTypeSelects[orgTypeId]);
    console.log(orgID);
    org = orgArray[orgTypeOptions[orgTypeId]][orgID]['Organisation'];
    console.log(org);
    $('#org_id').text(org['id']);
    $('#org_name').text(org['name']);
    $('#org_uuid').text(org['uuid']);
    $('#org_local').text(orgTypeOptions[$('#OrganisationTargetType').val()]);
}

function mergeOrganisationTypeToggle() {
    if ($('#OrganisationTargetType').val() == 0) {
        $('#orgsLocal').show();
        $('#orgsExternal').hide();
    } else {
        $('#orgsLocal').hide();
        $('#orgsExternal').show();
    }
}

function feedDistributionChange() {
    if ($('#FeedDistribution').val() == 4) $('#SGContainer').show();
    else $('#SGContainer').hide();
}

function checkUserPasswordEnabled() {
    if ($('#UserEnablePassword').is(':checked')) {
        $('#PasswordDiv').show();
    } else {
        $('#PasswordDiv').hide();
    }
}

function checkUserExternalAuth() {
    if ($('#UserExternalAuthRequired').is(':checked')) {
        $('#externalAuthDiv').show();
        $('#passwordDivDiv').hide();
    } else {
        $('#externalAuthDiv').hide();
        $('#passwordDivDiv').show();
    }
}

function toggleSettingSubGroup(group) {
    $('.subGroup_' + group).toggle();
}

function runHoverLookup(type, id) {
    $.ajax({
        success:function (html) {
            ajaxResults["hover"][type + "_" + id] = html;
            var element = $('#' + type + '_' + id + '_container');
            element.popover({
                title: attributeHoverTitle(id, type),
                content: html,
                placement: attributeHoverPlacement(element),
                html: true,
                trigger: 'manual',
                container: 'body'
            }).popover('show');
            $('#' + currentPopover).popover('destroy');
            currentPopover = type + '_' + id + '_container'
        },
        cache: false,
        url:"/attributes/hoverEnrichment/" + id,
    });
}

$(".cortex-json").click(function() {
    var cortex_data = $(this).data('cortex-json');
    cortex_data = htmlEncode(JSON.stringify(cortex_data, null, 2));
    var popupHtml = '<pre class="simplepre">' + cortex_data + '</pre>';
    popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';

});

// add the same as below for click popup
$(document).on( "click", ".eventViewAttributePopup", function() {
    $('#popover_box').empty();
    type = $(this).attr('data-object-type');
    id = $(this).attr('data-object-id');
    if (!(type + "_" + id in ajaxResults["persistent"])) {
        $.ajax({
            success:function (html) {
                ajaxResults["persistent"][type + "_" + id] = html;
            },
            async: false,
            cache: false,
            url:"/attributes/hoverEnrichment/" + id + "/1",
        });
    }
    if (type + "_" + id in ajaxResults["persistent"]) {
        var enrichment_popover = ajaxResults["persistent"][type + "_" + id];
        enrichment_popover += '<div class="close-icon useCursorPointer popup-close-icon" onClick="closeScreenshot();"></div>';
        $('#popover_box').html('<div class="screenshot_content">' + enrichment_popover + '</div>');
        $('#popover_box').show();
        $("#gray_out").fadeIn();
        $('#popover_box').css({'padding': '5px'});
        $('#popover_box').css( "maxWidth", ( $( window ).width() * 0.9 | 0 ) + "px" );
        $('#popover_box').css( "maxHeight", ( $( window ).width() - 300 | 0 ) + "px" );
        $('#popover_box').css( "overflow-y", "auto");

        var left = ($(window).width() / 2) - ($('#popover_box').width() / 2);
        $('#popover_box').css({'left': left + 'px'});
    }
    $('#' + currentPopover).popover('destroy');
});

function flashErrorPopover() {
    $('#popover_form').css( "minWidth", "200px");
    $('#popover_form').html($('#flashErrorMessage').html());
    $('#popover_form').show();
    var left = ($(window).width() / 2) - ($('#popover_form').width() / 2);
    $('#popover_form').css({'left': left + 'px'});
    $("#gray_out").fadeIn();
}

function attributeHoverTitle(id, type) {
  return `<span>Lookup results:</span>
		<i class="fa fa-search-plus useCursorPointer eventViewAttributePopup"
				style="float: right;"
				data-object-id="${id}"
				data-object-type="${type}">
	</i>`;
}

function attributeHoverPlacement(element) {
  var offset = element.offset(),
    topOffset = offset.top - $(window).scrollTop(),
    left = offset.left - $(window).scrollLeft(),
    viewportHeight = window.innerHeight,
    viewportWidth = window.innerWidth,
    horiz = 0.5 * viewportWidth - left,
    horizPlacement = horiz > 0 ? 'right' : 'left',
    popoverMaxHeight = .75 * viewportHeight;

  // default to top placement
  var placement = topOffset - popoverMaxHeight > 0 ? 'top' : horizPlacement;

  // more space on bottom
  if (topOffset < .5 * viewportHeight) {
    // will popup fit on bottom
    placement = popoverMaxHeight < topOffset ? 'bottom' : horizPlacement;
  }

  return placement;
}

$('body').on('click', function (e) {
  $('[data-toggle=popover]').each(function () {
    // hide any open popovers when the anywhere else in the body is clicked
    if (typeof currentPopover !== 'undefined') {
        if (!$(this).is(e.target) && $(this).has(e.target).length === 0 && $('.popover').has(e.target).length === 0) {
          $('#' + currentPopover).popover('destroy');
        }
    }
  });
});

function serverOwnerOrganisationChange(host_org_id) {
    if ($('#ServerOrganisationType').val() == "0" && $('#ServerLocal').val() == host_org_id) {
        $('#InternalDiv').show();
    } else {
        $('#ServerInternal').prop("checked", false);
        $('#InternalDiv').hide();
    }
}

function requestAPIAccess() {
    url = "/users/request_API/";
    $.ajax({
        type:"get",
        url:url,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data) {
            $(".loading").hide();
            handleGenericAjaxResponse(data);
        },
        error:function() {
            showMessage('fail', 'Something went wrong - could not request API access.');
        }
    });
}

function initPopoverContent(context) {
    for (var property in formInfoFields) {
        if (formInfoFields.hasOwnProperty(property)) {
            $('#' + property + 'InfoPopover').popover("destroy").popover({
                placement: 'right',
                html: 'true',
                trigger: 'hover',
                content: getFormInfoContent(property, '#' + context + formInfoFields[property])
            });
        }
    }
}

function getFormInfoContent(property, field) {
    var content = window[property + 'FormInfoValues'][$(field).val()];
    if (content === undefined || content === null) {
        return 'N/A';
    }
    return content;
}

function formCategoryChanged(id) {
    // fill in the types
    var options = $('#' + id +'Type').prop('options');
    $('option', $('#' + id +'Type')).remove();
    $.each(category_type_mapping[$('#' + id +'Category').val()], function(val, text) {
        options[options.length] = new Option(text, val);
    });
    // enable the form element
    $('#AttributeType').prop('disabled', false);
}

function malwareCheckboxSetter(context) {
    idDiv = "#" + context + "Category" +'Div';
    var value = $("#" + context + "Category").val();  // get the selected value
    // set the malware checkbox if the category is in the zip types
    $("#" + context + "Malware").prop('checked', formZipTypeValues[value] == "true");
}

function feedFormUpdate() {
    $('.optionalField').hide();
    switch($('#FeedSourceFormat').val()) {
        case 'freetext':
            $('#TargetDiv').show();
            $('#OverrideIdsDiv').show();
            $('#PublishDiv').show();
            if ($('#FeedTarget').val() != 0) {
                $('#TargetEventDiv').show();
                $('#DeltaMergeDiv').show();
            }
            $('#settingsCommonExcluderegexDiv').show();
            break;
        case 'csv':
            $('#TargetDiv').show();
            $('#OverrideIdsDiv').show();
            $('#PublishDiv').show();
            if ($('#FeedTarget').val() != 0) {
                $('#TargetEventDiv').show();
                $('#DeltaMergeDiv').show();
            }
            $('#settingsCsvValueDiv').show();
            $('#settingsCsvDelimiterDiv').show();
            $('#settingsCommonExcluderegexDiv').show();
            break;
    }
    if ($('#FeedInputSource').val() == 'local') {
        $('#DeleteLocalFileDiv').show();
        $('#HeadersDiv').hide();
    } else {
        $('#DeleteLocalFileDiv').hide();
        $('#HeadersDiv').show();
    }
}

function setContextFields() {
    if (showContext) {
        $('.context').show();
        $('#show_context').addClass("attribute_filter_text_active");
        $('#show_context').removeClass("attribute_filter_text");
    } else {
        $('.context').hide();
        $('#show_context').addClass("attribute_filter_text");
        $('#show_context').removeClass("attribute_filter_text_active");
    }
}

function toggleContextFields() {
    if (!showContext) {
        showContext = true;
    } else {
        showContext = false;
    }
    setContextFields();
}

function checkOrphanedAttributes() {
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            var color = 'red';
            var text = ' (Removal recommended)';
            if (data == '0') {
                color = 'green';
                text = ' (OK)';
            }
            $("#orphanedAttributeCount").html('<span class="' + color + '">' + data + text + '</span>');
        },
        complete:function() {
            $(".loading").hide();
        },
        type:"get",
        cache: false,
        url: "/attributes/checkOrphanedAttributes/",
    });
}

function checkAttachments() {
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            var color = 'red';
            var text = ' (Bad links detected)';
            if (data !== undefined && data.trim() == '0') {
                color = 'green';
                text = ' (OK)';
            }
            $("#orphanedFileCount").html('<span class="' + color + '">' + data + text + '</span>');
        },
        complete:function() {
            $(".loading").hide();
        },
        type:"get",
        cache: false,
        url: "/attributes/checkAttachments/",
    });
}

function loadTagTreemap() {
    $.ajax({
        async:true,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            $(".treemapdiv").html(data);
        },
        complete:function() {
            $(".loading").hide();
        },
        type:"get",
        cache: false,
        url: "/users/tagStatisticsGraph",
    });
}

function quickEditEvent(id, field) {
    $.ajax({
        async:true,
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        success:function (data, textStatus) {
            $("#" + field + "Field").html(data);
        },
        complete:function() {
            $(".loading").hide();
        },
        type:"get",
        cache: false,
        url: "/events/quickEdit/" + id + "/" + field,
    });
}

function selectAllInbetween(last, current) {
    if (last === false || last == current) return false;
    var from = $('#' + last).parent().parent().index();
    var to = $('#' + current).parent().parent().index();
    if (to < from) {
        var temp = from;
        from = to;
        to = temp;
    }
    $('.select_proposal, .select_attribute, .select').each(function (e) {
        if ($('#' + this.id).parent().parent().index() >= from && $('#' + this.id).parent().parent().index() <= to) {
            $(this).prop('checked', true);
        }
    });
}

$('.galaxy-toggle-button').click(function() {
    var element = $(this).data('toggle-type');
    if ($(this).children('span').hasClass('icon-minus')) {
        $(this).children('span').addClass('icon-plus');
        $(this).children('span').removeClass('icon-minus');
        $('#' + element + '_div').hide();
    } else {
        $(this).children('span').removeClass('icon-plus');
        $(this).children('span').addClass('icon-minus');
        $('#' + element + '_div').show();
    }
});


function addGalaxyListener(id) {
    var target_type = $(id).data('target-type');
    var target_id = $(id).data('target-id');
    var local = $(id).data('local');
    console.log(local);
    if (local) {
        local = 1;
    } else {
        local = 0;
    }
    popoverPopup(id, target_id + '/' + target_type + '/local:' + local, 'galaxies', 'selectGalaxyNamespace');
}

function quickSubmitGalaxyForm(cluster_ids, additionalData) {
    cluster_ids = cluster_ids === null ? [] : cluster_ids;
    var target_id = additionalData['target_id'];
    var scope = additionalData['target_type'];
    var local = additionalData['local'];
    var url = "/galaxies/attachMultipleClusters/" + target_id + "/" + scope + "/local:" + local;
    fetchFormDataAjax(url, function(formData) {
        $('body').append($('<div id="temp"/>').html(formData));
        $('#temp #GalaxyTargetIds').val(JSON.stringify(cluster_ids));
        if (target_id == 'selected') {
            $('#AttributeAttributeIds, #GalaxyAttributeIds').val(getSelected());
        }
        $.ajax({
            data: $('#GalaxyAttachMultipleClustersForm').serialize(),
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            success:function (data, textStatus) {
                if (target_id === 'selected') {
                    location.reload();
                } else {
                    if (scope == 'tag_collection') {
                        location.reload();
                    } else {
                        loadGalaxies(target_id, scope);
                        handleGenericAjaxResponse(data);
                    }
                }
            },
            error:function() {
                showMessage('fail', 'Could not add cluster.');
                loadGalaxies(target_id, scope);
            },
            complete:function() {
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
                $('#temp').remove();
            },
            type:"post",
            url: url
        });
    });
}

function checkAndSetPublishedInfo(skip_reload) {
    if (typeof skip_reload === "undefined") {
        skip_reload = false;
    }
    var id = $('#hiddenSideMenuData').data('event-id');
    if (id !== 'undefined' && !skip_reload) {
        $.get( "/events/checkPublishedStatus/" + id, function(data) {
            if (data == 1) {
                $('.published').removeClass('hidden');
                $('.not-published').addClass('hidden');
            } else {
                $('.published').addClass('hidden');
                $('.not-published').removeClass('hidden');
            }
        });
    }
}

$(document).keyup(function(e){
    if (e.keyCode === 27) {
    $("#gray_out").fadeOut();
        $("#popover_form").fadeOut();
        $("#popover_form_large").fadeOut();
        $("#popover_matrix").fadeOut();
        $("#screenshot_box").fadeOut();
        $("#popover_box").fadeOut();
        $("#confirmation_box").fadeOut();
        $(".loading").hide();
        resetForms();
    }
});

function closeScreenshot() {
    $("#popover_box").fadeOut();
    $("#screenshot_box").fadeOut();
    $("#gray_out").fadeOut();
}

function loadSightingGraph(id, scope) {
    $.get( "/sightings/viewSightings/" + id + "/" + scope, function(data) {
        $("#sightingsData").html(data);
    });
}

function checkRolePerms() {
    if ($("#RolePermission").val() == '0' || $("#RolePermission").val() == '1') {
        $('.readonlydisabled').prop('checked', false);
        $('.readonlydisabled').hide();
    } else {
        $('.readonlydisabled').show();
        $('.permFlags').show();
    }
    if ($("#RolePermSiteAdmin").prop('checked')) {
        $('.checkbox').prop('checked', true);
    }
}

function updateMISP() {
    $.get( "/servers/update", function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function submitMISPUpdate() {
    var formData = $('#PromptForm').serialize();
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: formData,
        success:function (data, textStatus) {
            $('#gitResult').text(data);
            $('#gitResult').removeClass('hidden');
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        cache: false,
        url:"/servers/update",
    });
}

function submitSubmoduleUpdate(clicked) {
    var $clicked = $(clicked);
    var submodule_path = $clicked.data('submodule');
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $clicked.removeClass('fa-download');
            $clicked.addClass('fa-spin fa-spinner');
        },
        dataType:"html",
        cache: false,
        success:function (formHTML, textStatus) {
            var $form = $(formHTML);
            $('body').append($form);
            var formData = $form.serialize();
            $.ajax({
                data: formData,
                success:function (data, textStatus) {
                    if (data.status) {
                        var job_sent = data.job_sent !== undefined ? data.job_sent : false;
                        var sync_result = data.sync_result !== undefined ? data.sync_result : '';
                        updateSubModulesStatus(data.output, job_sent, sync_result);
                    } else {
                        showMessage('error', 'Something went wrong');
                        $('#submoduleGitResultDiv').show();
                        $('#submoduleGitResult').removeClass('green').addClass('red').text(data.output);
                    }
                },
                error: function (data) {
                    showMessage('error', 'Something went wrong');
                    $('#submoduleGitResultDiv').show();
                    $('#submoduleGitResult').removeClass('green').addClass('red').text(data.output);
                },
                complete:function() {
                    $clicked.removeClass('fa-spin fa-spinner');
                    $clicked.addClass('fa-download');
                    $form.remove();
                },
                type:"post",
                cache: false,
                url:$form.attr('action'),
            });
        },
        url:'/servers/getSubmoduleQuickUpdateForm/' + (submodule_path !== undefined ? btoa(submodule_path) : ''),
    });
}

// Show $(id) if the enable parameter evaluates to true. Hide it otherwise
function checkAndEnable(id, enable) {
    if (enable) {
        $(id).show();
    } else {
        $(id).hide();
    }
}

// Show and enable checkbox $(id) if the enable parameter evaluates to true. Hide and disable it otherwise.
function checkAndEnableCheckbox(id, enable) {
    if (enable) {
        $(id).removeAttr("disabled");
        $(id).prop('checked', true);
    } else {
        $(id).prop('checked', false);
        $(id).attr("disabled", true);
    }
}

function enableDisableObjectRows(rows) {
    rows.forEach(function(i) {
        if ($("#Attribute" + i + "ValueSelect").length != 0) {
            checkAndEnableCheckbox("#Attribute" + i + "Save", $("#Attribute" + i + "ValueSelect").val() != "");
            $("#Attribute" + i + "ValueSelect").bind('input propertychange', function() {
                checkAndEnableCheckbox("#Attribute" + i + "Save", $(this).val() != "");
            })
        } else if ($("#Attribute" + i + "Attachment").length != 0) {
            checkAndEnableCheckbox("#Attribute" + i + "Save", $("#Attribute" + i + "Attachment").val() != "");
        } else {
            checkAndEnableCheckbox("#Attribute" + i + "Save", $("#Attribute" + i + "Value").val() != "");
        }
        $("#Attribute" + i + "Value").bind('input propertychange', function() {
            checkAndEnableCheckbox("#Attribute" + i + "Save", $(this).val() != "");
        });
        $("#Attribute" + i + "Attachment").on('change', function() {
            checkAndEnableCheckbox("#Attribute" + i + "Save", $("#Attribute" + i + "Attachment").val() != "");
        });
    });
}

function objectReferenceInput() {
    var types = ["Attribute", "Object"];
    var $targetSelect = $('[data-targetselect="targetSelect"]');
    for (var type in types) {
        for (var k in targetEvent[types[type]]) {
            if (targetEvent[types[type]][k]['uuid'] == $('#ObjectReferenceReferencedUuid').val()) {
                $targetSelect.val($('#ObjectReferenceReferencedUuid').val());
                changeObjectReferenceSelectOption($('#ObjectReferenceReferencedUuid').val(), {type: types[type]});
                $targetSelect.trigger('chosen:updated');
            }
        }
    }
}

function objectReferenceCheckForCustomRelationship() {
    var relationship_type_field = $('#ObjectReferenceRelationshipTypeSelect option:selected');
    var relationship_type = $(relationship_type_field).val();
    if (relationship_type == 'custom') {
        $('#ObjectReferenceRelationshipType').parent().removeClass('hidden');
    } else {
        $('#ObjectReferenceRelationshipType').parent().addClass('hidden');
    }
}

function add_basic_auth() {
    var headers = $('#FeedHeaders').val().split("\n");
    $('#FeedHeaders').val("");
    headers.forEach(function(header) {
        header = header.trim();
        if (header != "") {
            header = header.split(":");
            var key = header.shift();
            var value = header.join(":");
            if (key != 'Authorization') {
                $('#FeedHeaders').val($('#FeedHeaders').val() + key.trim() + ":" + value.trim() + "\n");
            }
        }
    });
    var basicAuth = $('#BasicAuthUsername').val().trim() + ':' + $('#BasicAuthPassword').val().trim();
    $('#FeedHeaders').val($('#FeedHeaders').val() + "Authorization: Basic " + btoa(basicAuth) + "\n");
    $('#basicAuthFormEnable').show();
    $('#basicAuthForm').hide();
}

function changeObjectReferenceSelectOption(selected, additionalData) {
    var uuid = selected;
    var type = additionalData.type;
    $('#ObjectReferenceReferencedUuid').val(uuid);
    if (type == "Attribute") {
        $('#targetData').html("");
        for (var k in targetEvent[type][uuid]) {
            if ($.inArray(k, ['uuid', 'category', 'type', 'value', 'to_ids']) !== -1) {
                $('#targetData').append('<div><span id="' + uuid + '_' + k + '_key" class="bold"></span>: <span id="' + uuid + '_' + k + '_data"></span></div>');
                $('#' + uuid + '_' + k + '_key').text(k);
                $('#' + uuid + '_' + k + '_data').text(targetEvent[type][uuid][k]);
            }
        }
    } else {
        $('#targetData').html("");
        for (var k in targetEvent[type][uuid]) {
            if (k == 'Attribute') {
                $('#targetData').append('<br /><div><span id="header" class="bold">Attributes:</span>');
                for (attribute in targetEvent[type][uuid]['Attribute']) {
                    for (k2 in targetEvent[type][uuid]['Attribute'][attribute]) {
                        if ($.inArray(k2, ['category', 'type', 'value', 'to_ids']) !== -1) {
                            $('#targetData').append('<div class="indent"><span id="' + targetEvent[type][uuid]['Attribute'][attribute]['uuid'] + '_' + k2 + '_key" class="bold"></span>: <span id="' + targetEvent[type][uuid]['Attribute'][attribute]['uuid'] + '_' + k2 + '_data"></span></div>');
                            $('#' + targetEvent[type][uuid]['Attribute'][attribute]['uuid'] + '_' + k2 + '_key').text(k2);
                            $('#' + targetEvent[type][uuid]['Attribute'][attribute]['uuid'] + '_' + k2 + '_data').text(targetEvent[type][uuid]['Attribute'][attribute][k2]);
                        }
                    }
                    $('#targetData').append('<br />');
                }
            } else {
                if ($.inArray(k, ['name', 'uuid', 'meta-category']) !== -1) {
                    $('#targetData').append('<div><span id="' + uuid + '_' + k + '_key" class="bold"></span>: <span id="' + uuid + '_' + k + '_data"></span></div>');
                    $('#' + uuid + '_' + k + '_key').text(k);
                    $('#' + uuid + '_' + k + '_data').text(targetEvent[type][uuid][k]);
                }
            }
        }
    }
}

function previewEventBasedOnUuids() {
    var currentValue = $("#EventExtendsUuid").val();
    if (currentValue == '') {
        $('#extended_event_preview').hide();
    } else {
        $.ajax({
            url: "/events/getEventInfoById/" + currentValue,
            type: "get",
            error: function() {
                $('#extended_event_preview').hide();
            },
            success: function(data) {
                $('#extended_event_preview').show();
                $('#extended_event_preview').html(data);
            }
        });
    }
}

function checkNoticeList(type) {
    var fields_to_check = {
        "attribute": ["category", "type"]
    }
    var warnings = [];
    $('#notice_message').html('<h4>Notices:</h4>');
    $('#notice_message').hide();
    fields_to_check[type].forEach(function(field_name) {
        if (field_name in notice_list_triggers) {
            var field_value = $('#' + type.ucfirst() + field_name.ucfirst()).val();
            if (field_value in notice_list_triggers[field_name]) {
                notice_list_triggers[field_name][field_value].forEach(function(notice) {
                    $('#notice_message').show();
                    $('#notice_message').append(
                        $('<div/>')
                            .append($('<span/>').text('['))
                            .append($('<a/>', {href: '/noticelists/view/' + notice['list_id'], class:'bold'}).text(notice['list_name']))
                            .append($('<span/>').text(']: '))
                            .append($('<span/>').text(notice['message']['en']))
                    );
                });
            }
        }
    });

}

$(document).ready(function() {
    $('#quickFilterField').bind("enterKey",function(e){
        $('#quickFilterButton').trigger("click");
    });
    $('#quickFilterField').keyup(function(e){
        if(e.keyCode == 13)
        {
            $('#quickFilterButton').trigger("click");
        }
    });
    $(".queryPopover").click(function() {
        url = $(this).data('url');
        id = $(this).data('id');
        $.get(url + '/' + id, function(data) {
            $('#popover_form').html(data);
            openPopup('#popover_form');
        });
    });
    $('.servers_default_role_checkbox').click(function() {
        var id = $(this).data("id");
        var state = $(this).is(":checked");
        $(".servers_default_role_checkbox").not(this).attr('checked', false);
        $.ajax({
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            success:function (data, textStatus) {
                handleGenericAjaxResponse(data);
            },
            complete:function() {
                $(".loading").hide();
            },
            type:"get",
            cache: false,
            url: '/admin/roles/set_default/' + (state ? id : ""),
        });
    });
    // clicking on an element with this class will select all of its contents in a
    // single click
    $('.quickSelect').click(function() {
        var range = document.createRange();
        var selection = window.getSelection();
        range.selectNodeContents(this);
        selection.removeAllRanges();
        selection.addRange(range);
    });
    $(".cortex-json").click(function() {
        var cortex_data = $(this).data('cortex-json');
        cortex_data = htmlEncode(JSON.stringify(cortex_data, null, 2));
        var popupHtml = '<pre class="simplepre">' + cortex_data + '</pre>';
        popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
        $('#popover_box').html(popupHtml);
        $('#popover_box').show();
        $('#popover_box').css({'padding': '5px'});
        left = ($(window).width() / 2) - ($('#popover_box').width() / 2);
        if (($('#popover_box').height() + 250) > $(window).height()) {
            $('#popover_box').height($(window).height() - 250);
            $('#popover_box').css("overflow-y", "scroll");
            $('#popover_box').css("overflow-x", "hidden");
        }
        $('#popover_box').css({'left': left + 'px'});
        $("#gray_out").fadeIn();
    });
    $('.add_object_attribute_row').click(function() {
        var template_id = $(this).data('template-id');
        var object_relation = $(this).data('object-relation');
        var k = $('#last-row').data('last-row');
        var k = k+1;
        $('#last-row').data('last-row', k);
        url = "/objects/get_row/" + template_id + "/" + object_relation + "/" + k;
        $.get(url, function(data) {
            $('#row_' + object_relation + '_expand').before($(data).fadeIn()).html();
            var $added_row = $('#row_' + object_relation + '_expand').prev().prev();
            $added_row.find('select.Attribute_value_select option:first').attr('disabled', true);
        });
    });
    $('.quickToggleCheckbox').toggle(function() {
        var url = $(this).data('checkbox-url');
    });
    $(".correlation-expand-button").on("click", function() {
        $(this).parent().children(".correlation-expanded-area").show();
        $(this).parent().children(".correlation-collapse-button").show();
        $(this).hide();
    });
    $(".correlation-collapse-button").on("click", function() {
        $(this).parent().children(".correlation-expanded-area").hide();
        $(this).parent().children(".correlation-expand-button").show();
        $(this).hide();
    });
});

function queryEventLock(event_id, user_org_id) {
    if (tabIsActive) {
        $.ajax({
            url: "/events/checkLocks/" + event_id,
            type: "get",
            success: function(data, statusText, xhr) {
                 if (xhr.status == 200) {
                     if ($('#event_lock_warning').length != 0) {
                         $('#event_lock_warning').remove();
                     }
                     if (data != '') {
                         $('#main-view-container').append(data);
                     }
                 }
            }
        });
    }
    setTimeout(function() { queryEventLock(event_id, user_org_id); }, 5000);
}

function checkIfLoggedIn() {
    if (tabIsActive) {
        $.get("/users/checkIfLoggedIn.json", function(data) {
            if (data.slice(-2) !== 'OK') {
                window.location.replace(baseurl + "/users/login");
            }
        });
    }
    setTimeout(function() { checkIfLoggedIn(); }, 5000);
}

function insertRawRestResponse() {
    $('#rest-response-container').append('<pre id="raw-response-container" />');
    $('#raw-response-container').text($('#rest-response-hidden-container').text());
}

function insertHTMLRestResponse() {
    $('#rest-response-container').append('<div id="html-response-container" style="border: 1px solid blue; padding:5px;" />');
    $('#html-response-container').html($('#rest-response-hidden-container').text());
}

function insertJSONRestResponse() {
    $('#rest-response-container').append('<p id="json-response-container" style="border: 1px solid blue; padding:5px; overflow-wrap: break-word;" />');
    var parsedJson = syntaxHighlightJson($('#rest-response-hidden-container').text());
    $('#json-response-container').html(parsedJson);
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
            var cls = 'json_number';
            if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                            cls = 'json_key';
                    } else {
                            cls = 'json_string';
                    }
            } else if (/true|false/.test(match)) {
                    cls = 'json_boolean';
            } else if (/null/.test(match)) {
                    cls = 'json_null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
    });
}

function jsonToNestedTable(json, header, table_classes) {
    if (typeof json == 'string') {
        json = JSON.parse(json);
    }
    if (Object.keys(json).length == 0) {
        return '';
    }
    header = header === undefined ? [] : header;
    table_classes = table_classes === undefined ? [] : table_classes;
    var $table = $('<table></table>');
    table_classes.forEach(function(classname) {
        $table.addClass(classname);
    });
    if (header.length > 0) {
        var $header = $('<thead><tr></tr></thead>');
        header.forEach(function(col) {
            $header.child().append($('<td></td>').text(col));
        });
        $table.append($header);
    }
    var $body = $('<tbody></tbody>');
    Object.keys(json).forEach(function(k) {
        var value = json[k];
        if (typeof value === 'object') {
            value = JSON.stringify(value);
        }
        $body.append(
            $('<tr></tr>')
                .append($('<td></td>').text(k))
                .append($('<td></td>').text(value))
        );
    });
    $table.append($body);
    return $table[0].outerHTML;
}

function liveFilter() {
    var lookupString = $('#liveFilterField').val();
    if (lookupString == '') {
        $('.live_filter_target').each(function() {
            $(this).parent().show();
        });
    } else {
        $('.live_filter_target').each(function() {
            $(this).parent().hide();
        });
        $('.live_filter_target').each(function() {
            if ($(this).text().indexOf(lookupString) >= 0) {
                $(this).parent().show();
            }
        });
    }
}

function sparklineBar(elemId, data, lineCount) {
    data = d3.csv.parse(data);
    var y_max = 0;
    data.forEach(function(e) {
        e = parseInt(e.val);
        y_max = e > y_max ? e : y_max;
    });
    var WIDTH      = 50;
    var HEIGHT     = 25;
    var DATA_COUNT = lineCount;
    var BAR_WIDTH  = (WIDTH - DATA_COUNT) / DATA_COUNT;
    var x    = d3.scale.linear().domain([0, DATA_COUNT]).range([0, WIDTH]);
    var y    = d3.scale.linear().domain([0, y_max]).range([0, HEIGHT]);

    var distributionGraphBarTooltip = d3.select("body").append("div")
        .attr("class", "distributionGraphBarTooltip")
        .style("opacity", 0);

    var svg = d3.select(elemId).append('svg')
      .attr('width', WIDTH)
      .attr('height', HEIGHT)
      .append('g');
    svg.selectAll('.bar').data(data)
      .enter()
      .append('g')
        .attr('title', function(d, i) { return d.scope + ': ' + d.val })
        .attr('class', 'DGbar')
      .append('rect')
        .attr('class', 'bar')
        .attr('x', function(d, i) { return x(i); })
        .attr('y', function(d, i) { return HEIGHT - y(d.val); })
        .attr('width', BAR_WIDTH)
        .attr('height', function(d, i) { return y(d.val); })
        .attr('fill', '#3465a4');

        $('.DGbar').tooltip({container: 'body'});
}

function generic_picker_move(scope, direction) {
    if (direction === 'right') {
        $('#' + scope + 'Left option:selected').remove().appendTo('#' + scope + 'Right');
    } else {
        $('#' + scope + 'Right option:selected').remove().appendTo('#' + scope + 'Left');
    }
}


function submit_feed_overlap_tool(feedId) {
    var result = {"Feed": [], "Server": []};
    $('#FeedLeft').children().each(function() {
        result.Feed.push($(this).val());
    });
    $('#ServerLeft').children().each(function() {
        result.Server.push($(this).val());
    });
    $.ajax({
        beforeSend: function (XMLHttpRequest) {
            $(".loading").show();
        },
        data: result,
        success:function (data, textStatus) {
            if (!isNaN(data)) {
                $('#feed_coverage_bar').text(data + '%');
                $('#feed_coverage_bar').css('width', data + '%');
            } else {
                handleGenericAjaxResponse({'saved':false, 'errors':['Something went wrong. Received response not in the expected format.']});
            }
        },
        error:function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Could not complete the requested action.']});
        },
        complete:function() {
            $(".loading").hide();
        },
        type:"post",
        cache: false,
        url:"/feeds/feedCoverage/" + feedId,
    });
}

function changeTaxonomyRequiredState(checkbox) {
    var checkbox_state = $(checkbox).is(":checked");
    var taxonomy_id = $(checkbox).data('taxonomy-id');
    fetchFormDataAjax('/taxonomies/toggleRequired/' + taxonomy_id, function(formData) {
        $.ajax({
            data: $(formData).serialize(),
            success:function (data, textStatus) {
                handleGenericAjaxResponse({'saved':true, 'success':['Taxonomy\'s required state toggled.']});
            },
            error:function() {
                $(checkbox).prop('checked', !$(checkbox).prop('checked'));
                handleGenericAjaxResponse({'saved':false, 'errors':['Could not toggle the required state of the taxonomy.']});
            },
            async:"false",
            type:"post",
            cache: false,
            url: '/taxonomies/toggleRequired/' + taxonomy_id,
        });
    });
}

function fetchFormDataAjax(url, callback) {
    var formData = false;
    $.ajax({
        data: '[]',
        success:function (data, textStatus) {
            callback(data);
        },
        error:function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Request failed due to an unexpected error.']});
        },
        async: false,
        type:"get",
        cache: false,
        url: url
    });
}

function moveIndexRow(id, direction, endpoint) {
    var row = $('#row_' + id);
    $.ajax({
        url: baseurl + endpoint + '/' + id + '/' + direction,
        type: 'GET',
        success: function(data) {
            if (direction === 'up') {
                if (row.prev().length) {
                    row.insertBefore(row.prev());
                }
            } else {
                if (row.next().length) {
                    row.insertAfter(row.next());
                }
            }
            handleGenericAjaxResponse({'saved':true, 'success':['Server priority changed.']});
        },
        error: function(data) {
            handleGenericAjaxResponse({'saved':false, 'errors':['Something went wrong, could not change the priority as requested.']});
        }
    });
}

function checkRoleEnforceRateLimit() {
    if ($("#RoleEnforceRateLimit").is(':checked')) {
        $('#rateLimitCountContainer').show();
    } else {
        $('#rateLimitCountContainer').hide();
    }
}

(function(){
    "use strict";
    $(".datepicker").datepicker({
        format: 'yyyy-mm-dd',
    });
}());
