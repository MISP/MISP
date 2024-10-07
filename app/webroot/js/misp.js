/* Codacy comment to notify that baseurl is a read-only global variable. */
/* global baseurl */

String.prototype.ucfirst = function() {
    return this.charAt(0).toUpperCase() + this.slice(1);
}

if (!String.prototype.startsWith) {
  String.prototype.startsWith = function(searchString, position) {
    position = position || 0;
    return this.indexOf(searchString, position) === position;
  };
}

function escapeHtml(unsafe) {
    if (typeof unsafe === "boolean" || typeof unsafe === "number") {
        return unsafe;
    }

    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function copyToClipboard(element) {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val($(element).val()).select();
    document.execCommand("copy");
    $temp.remove();
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

function rgb2hex(rgb) {
    rgb = rgb.match(/^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/);
    function hex(x) {
        return ("0" + parseInt(x).toString(16)).slice(-2);
    }
    return "#" + hex(rgb[1]) + hex(rgb[2]) + hex(rgb[3]);
}

function xhrFailCallback(xhr) {
    if (xhr.status === 0) {
        showMessage('fail', 'Something went wrong – server is not responding.');
    } else if (xhr.status === 401) {
        showMessage('fail', 'Unauthorized. Please reload page to log again.');
    } else if (xhr.status === 403 || xhr.status === 405) {
        showMessage('fail', 'Not allowed.');
    } else if (xhr.status === 404) {
        showMessage('fail', 'Resource not found.');
    } else {
        showMessage('fail', 'Something went wrong - the queried function returned an exception. Contact your administrator for further details.');
    }
}

function xhr(options) {
    options.beforeSend = options.beforeSend || function() {
        $(".loading").show();
    };
    options.complete = options.complete || function() {
        $(".loading").hide();
    }
    options.error = options.error || xhrFailCallback;
    options.cache = options.cache || false;

    if (!options.url.startsWith('http://') && !options.url.startsWith('https://')) {
        options.url = baseurl + options.url;
    }

    return $.ajax(options);
}

function deleteObject(type, action, id) {
    var url = baseurl + "/" + type + "/" + action + "/" + id;
    $.get(url, openConfirmation).fail(xhrFailCallback)
}

function quickDeleteSighting(id, rawId, context) {
    var url = baseurl + "/sightings/quickDelete/" + id + "/" + rawId + "/" + context;
    $.get(url, openConfirmation).fail(xhrFailCallback)
}

function fetchAddSightingForm(type, attribute_id, onvalue) {
    var url = baseurl + "/sightings/quickAdd/" + attribute_id + "/" + type;
    if (onvalue) {
        url = url + "/1";
    } else {
        url = url + "/0";
    }
    $.get(url, openConfirmation).fail(xhrFailCallback);
}

function flexibleAddSighting(clicked, type, attribute_id, placement) {
    var $clicked = $(clicked);
    var hoverbroken = false;
    $clicked.off('mouseleave.temp').on('mouseleave.temp', function() {
        hoverbroken = true;
    });
    setTimeout(function() {
        $clicked.off('mouseleave.temp');
        if ($clicked.is(":hover") && !hoverbroken) {
            var html = '<div>'
                + '<button class="btn btn-primary" onclick="addSighting(\'' + type + '\', \'' + attribute_id + '\')">This attribute</button>'
                + '<button class="btn btn-primary" style="margin-left:5px;" onclick="fetchAddSightingForm(\'' + type + '\', \'' + attribute_id + '\', true)">Global value</button>'
                + '</div>';
            openPopover(clicked, html, true, placement);
        }
    }, 1000);
}

function publishPopup(id, type, scope) {
    scope = scope === undefined ? 'events' : scope;
    var action = "alert";
    if (type === "publish") action = "publish";
    if (type === "unpublish") action = "unpublish";
    if (type === "sighting") action = "publishSightings";
    $.get(baseurl + "/" + scope + "/" + action + "/" + id, openConfirmation).fail(xhrFailCallback);
}

function delegatePopup(id) {
    simplePopup(baseurl + "/event_delegations/delegateEvent/" + id);
}

function genericPopup(url, popupTarget, callback) {
    var $popupTarget = $(popupTarget);
    $.get(url, function(data) {
        $popupTarget.html(data);
        $popupTarget.fadeIn();
        var left = ($(window).width() / 2) - ($(popupTarget).width() / 2);
        $popupTarget.css({'left': left + 'px'});
        $("#gray_out").fadeIn();
        if (callback !== undefined) {
            callback();
        }
    }).fail(xhrFailCallback)
}

function screenshotPopup(url, title) {
    if (!url.startsWith('data:image/')) {
        url = url.slice(0, -1);
    }
    url = $('<div>').text(url).html();

    var img = document.createElement('img');
    img.classList.add('hidden', 'screenshot_box-content');
    img.src = url;
    img.title = title;
    img.alt = title;
    img.onload = function() {
        $(this).show();
        $(this).parent().parent().find('.fa-spinner').remove();
    }
    img.onerror = function() {
        showMessage('fail', 'Something went wrong - could not load attachment');
        closeScreenshot();
    }

    var popupHtml = '<it class="fa fa-spin fa-spinner" style="font-size: xx-large; color: white; position: fixed; left: 50%; top: 50%;"></it>';
    popupHtml += '<div class="screenshot-img-box"></div>';
    popupHtml += '<div class="close-icon useCursorPointer" onclick="closeScreenshot()"></div>';
    if (!url.startsWith('data:image/')) {
        popupHtml += '<a class="close-icon useCursorPointer fa fa-expand" style="right: 20px; background: black; color: white; text-decoration: none;" target="_blank" href="' + url + '"></a>';
    }
    popupHtml += '<div style="height: 20px;"></div>'; // see bottom of image for large one

    var $screenshotBox = $("<div id=\"screenshot_box\"></div>").appendTo("body");
    $screenshotBox.html(popupHtml);
    $screenshotBox.css({
        display: 'block',
        top: (document.documentElement.scrollTop + 100) + 'px'
    });
    $screenshotBox.find(".screenshot-img-box").append(img);
    $("#gray_out").fadeIn();
}

function editTemplateElement(type, id) {
    simplePopup(baseurl + "/template_elements/edit/" + type + "/" + id);
}

function cancelPrompt(isolated) {
    if (isolated == undefined) {
        $("#gray_out").fadeOut();
    }
    $("#popover_form").fadeOut();
    $("#confirmation_box").fadeOut().empty();
    $('.have-a-popover').popover('destroy');
}

function submitDeletion(context_id, action, type, id) {
    var context = 'event';
    if (type == 'template_elements') context = 'template';
    var formData = $('#PromptForm').serialize();
    xhr({
        data: formData,
        success:function (data) {
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
        type: "post",
        url: "/" + type + "/" + action + "/" + id,
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
    xhr({
        data: formData,
        success:function (data, textStatus) {
            handleGenericAjaxResponse(data);
            var org = "/" + $('#org_id').text();
            updateIndex(id, 'event');
            $.get(baseurl + "/sightings/listSightings/" + rawid + "/" + context + org, function(data) {
                $("#sightingsData").html(data);
            }).fail(xhrFailCallback);
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
        },
        type:"post",
        url: "/sightings/quickDelete/" + id + "/" + rawid + "/" + context,
    });
}

function toggleSetting(e, setting, id) {
    e.preventDefault();
    e.stopPropagation();
    switch (setting) {
        case 'warninglist_enable':
            formID = '#WarninglistIndexForm';
            dataDiv = '#WarninglistData';
            replacementForm = baseurl + '/warninglists/getToggleField/';
            searchString = 'enabled';
            var successCallback = function(setting) {
                var icon = $(e.target).closest('tr').find('[data-path="Warninglist.enabled"] .fa')
                if (setting) {
                    icon.removeClass('fa-times').addClass('fa-check')
                    $(e.target).removeClass('fa-play').addClass('fa-stop')
                } else {
                    icon.removeClass('fa-check').addClass('fa-times')
                    $(e.target).removeClass('fa-stop').addClass('fa-play')
                }
            }
            break;
        case 'favourite_tag':
            formID = '#FavouriteTagIndexForm';
            dataDiv = '#FavouriteTagData';
            replacementForm = baseurl + '/favourite_tags/getToggleField/';
            searchString = 'Adding';
            break;
        case 'activate_object_template':
            formID = '#ObjectTemplateIndexForm';
            dataDiv = '#ObjectTemplateData';
            replacementForm = baseurl + '/ObjectTemplates/getToggleField/';
            searchString = 'activated';
            break;
        case 'noticelist_enable':
            formID = '#NoticelistIndexForm';
            dataDiv = '#NoticelistData';
            replacementForm = baseurl + '/noticelists/getToggleField/';
            searchString = 'enabled';
            break;
    }
    $(dataDiv).val(id);
    var formData = $(formID).serialize();
    xhr({
        data: formData,
        success:function (data) {
            var result = data;
            if (result.success) {
                var setting = false;
                if (result.success.indexOf(searchString) > -1) setting = true;
                if (typeof successCallback === 'function') {
                    successCallback(setting)
                } else {
                    $('#' + e.target.id).prop('checked', setting);
                }
            }
            handleGenericAjaxResponse(data);
        },
        complete:function() {
            $.get(replacementForm, function(data) {
                $('#hiddenFormDiv').html(data);
            }).fail(xhrFailCallback);
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        error:function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Request failed due to an unexpected error.']});
        },
        type: "post",
        url: $(formID).attr('action'),
    });
}

function initiatePasswordReset(id) {
    $.get(baseurl + "/users/initiatePasswordReset/" + id, openConfirmation).fail(xhrFailCallback)
}

function submitPasswordReset(id) {
    var formData = $('#PromptForm').serialize();
    xhr({
        data: formData,
        success: function (data) {
            handleGenericAjaxResponse(data);
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type: "post",
        url: "/users/initiatePasswordReset/" + id,
    });
}

function submitMessageForm(url) {
    if (!$('#PostMessage').val()) {
        showMessage("fail", "Cannot submit empty message.");
    } else {
        var message = $('#PostMessage').val()
        fetchFormDataAjax(url, function (formData) {
            var $formData = $(formData);
            $formData.find('#PostMessage').val(message);
            $.ajax({
                data: $formData.find('form').serialize(),
                beforeSend: function () {
                    $(".loading").show();
                },
                success: function (data) {
                    showMessage("success", "Message added.");
                    $('#top').html(data);
                },
                error: function () {
                    showMessage('fail', 'Could not add message.');
                },
                complete: function () {
                    $(".loading").hide();
                },
                type: "post",
                url: $formData.find('form').attr('action')
            });
        });
    }
}

function acceptObject(type, id) {
    var name = '#ShadowAttribute_' + id + '_accept';
    var formData = $(name).serialize();
    $.ajax({
        data: formData,
        success: function (data) {
            updateIndex(null, 'event');
            eventUnpublish();
            handleGenericAjaxResponse(data);
        },
        error: xhrFailCallback,
        type: "post",
        cache: false,
        url: baseurl + "/shadow_attributes/accept/" + id,
    });
}

function toggleCorrelation(id, skip_reload) {
    if (typeof skip_reload === "undefined") {
        skip_reload = false;
    }
    xhr({
        data: $('#PromptForm').serialize(),
        success:function (data) {
            handleGenericAjaxResponse(data, skip_reload);
            $("#correlation_toggle_" + id).prop('checked', !$("#correlation_toggle_" + id).is(':checked'));
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        url: '/attributes/toggleCorrelation/' + id,
    });
}

function toggleToIDS(id, skip_reload) {
    if (typeof skip_reload === "undefined") {
        skip_reload = false;
    }
    xhr({
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
        url: '/attributes/editField/' + id ,
    });
}

function eventUnpublish() {
    $('.publishButtons').show();
    $('.exportButtons').hide();
    $('.published').hide();
    $('.notPublished').show();
}

function updateIndex(id, context, callback) {
    var url, div;
    if (context === 'event') {
        if (typeof currentUri == 'undefined') {
            location.reload();
            return true;
        }
        url = currentUri;
        div = "#attributes_div";
    } else if (context === 'template') {
        url = "/template_elements/index/" + id;
        div = "#templateElements";
    }
    xhr({
        dataType: "html",
        success: function (data) {
            $(div).html(data);
            if (typeof callback !== "undefined") {
                callback("success");
            }

            if (typeof genericPopupCallback !== "undefined") {
                genericPopupCallback("success");
            } else {
                console.log("genericPopupCallback function not defined");
            }
            if (typeof timelinePopupCallback !== "undefined") {
                timelinePopupCallback("success");
            } else {
                console.log("timelinepopupcallback function not defined");
            }
        },
        url: url,
    });
}

function updateFieldOnSuccess($td, type, id, field) {
    var objectType = type === 'Object' ? 'objects' : 'attributes';
    $.ajax({
        beforeSend: function () {
            if (field !== 'timestamp') {
                $(".loading").show();
            }
        },
        dataType: "html",
        cache: false,
        success: function (data) {
            if (field !== 'timestamp') {
                $(".loading").hide();
                $td.find('.inline-field-placeholder').remove();
                $td.find('.inline-field-solid').html(data).show();
            } else {
                $td.parent().find('td.timestamp').html(data);
            }
            popoverStartup(); // reactive popovers
        },
        error: xhrFailCallback,
        url: baseurl + "/" + objectType +"/fetchViewValue/" + id + "/" + field,
    });
}

function activateField($td, type, id, field) {
    resetEditHoverForms();
    if (type === 'denyForm') {
        return;
    }
    var objectType = type === 'Object' ? 'objects' : 'attributes';
    var name = '#' + type + '_' + id + '_' + field;

    xhr({
        dataType: "html",
        success: function (data) {
            var $placeholder = $('<div class="inline-field-placeholder"></div>').html(data);
            $td.find(".inline-field-solid").before($placeholder);
            postActivationScripts($td, name, type, id, field);
            $td.find(".inline-field-solid").hide();
        },
        url: "/" + objectType + "/fetchEditForm/" + id + "/" + field,
    });
}

//if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
//If a user presses enter, submit the form
function postActivationScripts($td, name, type, id, field) {
    var $field = $(name + '_field');
    $field.focus();
    inputFieldButtonActive($field);
    if (field === 'value' || field === 'comment') {
        autoresize($field[0]);
        $field.on('keyup', function () {
            autoresize(this);
        });
    }

    $(name + '_form').submit(function(e){
        e.preventDefault();
        submitForm($td, type, id, field);
        return false;
    }).bind("focusout", function() {
        inputFieldButtonPassive($field);
    }).bind("focusin", function(){
        inputFieldButtonActive($field);
    });

    var $inlineInputContainer = $field.closest('.inline-input-container');

    $inlineInputContainer.children('.inline-input-accept').bind('click', function() {
        submitForm($td, type, id, field);
    });

    $inlineInputContainer.children('.inline-input-decline').bind('click', function() {
        resetEditHoverForms();
    });
}

function quickEditHover(td, type, id, field) {
    var $td = $(td);
    $td.find('#quickEditButton').remove(); // clean all similar if exist
    var $div = $('<div id="quickEditButton"></div>');
    $div.addClass('quick-edit-row-div');
    var $span = $('<span></span>');
    $span.addClass('fa-as-icon fa fa-edit');
    $span.css('font-size', '12px');
    $div.append($span);
    $td.find(".inline-field-solid").append($div);

    $span.click(function() {
        activateField($td, type, id, field);
    });

    $td.off('mouseleave').on('mouseleave', function() {
        $div.remove();
    });
}

function addSighting(type, attribute_id) {
    var $sightingForm = $('#SightingForm');
    $('input[name="data[Sighting][type]"]', $sightingForm).val(type);
    $('input[name="data[Sighting][id]"]', $sightingForm).val(attribute_id);
    $.ajax({
        data: $sightingForm.serialize(),
        cache: false,
        success: function (data) {
            handleGenericAjaxResponse(data);
            var result = data;
            if (result.saved == true) {
                // Update global sighting counter
                $('.sightingsCounter').each(function() {
                    $(this).html(parseInt($(this).html()) + 1);
                });
                updateIndex(null, 'event');
            }
        },
        error: function(xhr) {
            xhrFailCallback(xhr);
            updateIndex(null, 'event');
        },
        type: "post",
        url: baseurl + "/sightings/add/",
    });
}

function resetEditHoverForms() {
    $('.inline-field-solid').show();
    $('.inline-field-placeholder').remove();
}

function resetForms() {
    $('.inline-field-solid').show();
    $('.inline-field-placeholder').hide();
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
function submitForm($td, type, id, field) {
    var object_type = 'attributes';
    var name = '#' + type + '_' + id + '_' + field;
    if (type === 'Object') {
        object_type = 'objects';
    }
    $.ajax({
        data: $(name + '_field').closest("form").serialize(),
        cache: false,
        success: function (data) {
            handleAjaxEditResponse($td, data, type, id, field);
        },
        error: function(xhr) {
            xhrFailCallback(xhr);
            updateIndex(null, 'event');
        },
        type: "post",
        url: baseurl + "/" + object_type + "/editField/" + id
    });
    $(name + '_field').unbind("keyup");
    $(name + '_form').unbind("focusout");
    return false;
}

// Event attributes and attributes index and search
(function() {
    $(document.body).on('click', '.correlation-toggle', function() {
        var attribute_id = $(this).parents('tr').data('primary-id');
        getPopup(attribute_id, 'attributes', 'toggleCorrelation', '', '#confirmation_box');
        return false;
    });
    $(document.body).on('click', '.toids-toggle', function() {
        var attribute_id = $(this).parents('tr').data('primary-id');
        getPopup(attribute_id, 'attributes', 'toggleToIDS', '', '#confirmation_box');
        return false;
    });
    $(document.body).on('click', '.screenshot', function() {
        screenshotPopup($(this).attr('src'), $(this).attr('title'));
    });
    // Show quick edit hover icon for attributes and objects
    $(document.body).on('mouseenter', '[data-edit-field]', function() {
        var $tr = $(this).parents('tr');
        var objectId = $tr.data('primary-id');
        var type = $tr.attr('id').startsWith('Object') ? 'Object' : 'Attribute';
        var field = $(this).data('edit-field');
        quickEditHover(this, type, objectId, field);
    });
    // Show popover with advanced sightings information about given or selected attributes
    $(document.body).on('click', '.sightings_advanced_add', function(e) {
        e.preventDefault();
        var object_context = $(this).data('object-context');
        var object_id = $(this).data('object-id');
        if (object_id === 'selected') {
            var selected = [];
            $(".select_attribute:checked").each(function() {
                selected.push($(this).data("id"));
            });
            object_id = selected.join('|');
        }
        var url = baseurl + "/sightings/advanced/" + object_id + "/" + object_context;
        genericPopup(url, '#popover_box');
    });
})();

function quickSubmitTagForm(selected_tag_ids, addData) {
    var event_id = addData.id;
    var localFlag = '';
    if (undefined != addData['local'] && addData['local']) {
        localFlag = '/local:1';
    }
    var url = baseurl + "/events/addTag/" + event_id + localFlag;
    fetchFormDataAjax(url, function(formData) {
        var $formData = $(formData);
        $formData.find('#EventTag').val(JSON.stringify(selected_tag_ids));
        xhr({
            data: $formData.serialize(),
            success: function (data) {
                handleGenericAjaxResponse(data);
            },
            error: function() {
                showMessage('fail', 'Could not add tag.');
            },
            complete: function() {
                loadEventTags(event_id);
                loadGalaxies(event_id, 'event');

                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
            },
            type: "post",
            url: url
        });
    });
}

function quickSubmitAttributeTagForm(selected_tag_ids, addData) {
    var attribute_id = addData.id;
    var localFlag = '';
    if (undefined != addData['local'] && addData['local']) {
        localFlag = '/local:1';
    }
    var url = baseurl + "/attributes/addTag/" + attribute_id + localFlag;
    fetchFormDataAjax(url, function(formData) {
        var $formData = $(formData);
        $formData.find('#AttributeTag').val(JSON.stringify(selected_tag_ids));
        if (attribute_id === 'selected') {
            $formData.find('#AttributeAttributeIds').val(getSelected());
        }
        xhr({
            data: $formData.serialize(),
            success:function (data) {
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
    var url = baseurl + "/tag_collections/addTag/" + tag_collection_id + localFlag;
    fetchFormDataAjax(url, function(formData) {
        var $formData = $(formData);
        $formData.find('#TagCollectionTag').val(JSON.stringify(selected_tag_ids));
        xhr({
            data: $formData.serialize(),
            success:function (data) {
                handleGenericAjaxResponse(data);
                refreshTagCollectionRow(tag_collection_id);
            },
            error:function() {
                showMessage('fail', 'Could not add tag.');
                refreshTagCollectionRow(tag_collection_id);
            },
            complete:function() {
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
            },
            type:"post",
            url: url
        });
    });
}

function refreshTagCollectionRow(tag_collection_id) {
    $.ajax({
        type:"get",
        url: baseurl + "/tag_collections/getRow/" + tag_collection_id,
        error:function() {
            showMessage('fail', 'Could not fetch updates to the modified row.');
        },
        success: function (data) {
            $('[data-row-id="' + tag_collection_id + '"]').replaceWith(data);
        }
    });
}

function modifyTagRelationship() {
    event.preventDefault();
    var $form = $(event.target);
    var action = $form.attr("action");

    $.ajax({
       type: "post",
       url: action,
       data: $form.serialize(),
       error: xhrFailCallback,
       success: function (data) {
           if (data.saved) {
               $('#genericModal').modal('hide');
               if ("attribute_id" in data.data) {
                   var attribute_id = data.data.attribute_id;
                   loadAttributeTags(attribute_id);
                   loadGalaxies(attribute_id, 'attribute');
               } else {
                   var event_id = data.data.event_id;
                   loadEventTags(event_id);
                   loadGalaxies(event_id, 'event');
               }
           }
       }
    });

    return false;
}

function handleAjaxEditResponse($td, data, type, id, field) {
    var responseArray = data;
    if (type === 'Attribute') {
        if (responseArray.saved) {
            var msg = responseArray.success !== undefined ? responseArray.success : responseArray.message;
            showMessage('success', msg);
            updateFieldOnSuccess($td, type, id, field);
            updateFieldOnSuccess($td, type, id, 'timestamp');
            eventUnpublish();
        } else {
            showMessage('fail', 'Validation failed: ' + responseArray.errors.value);
            updateFieldOnSuccess($td, type, id, field);
        }
    } else if (type === 'ShadowAttribute') {
        updateIndex(null, 'event');
    } else if (type === 'Object') {
        if (responseArray.saved) {
            showMessage('success', responseArray.message);
            updateFieldOnSuccess($td, type, id, field);
            updateFieldOnSuccess($td, type, id, 'timestamp');
            eventUnpublish();
        } else {
            showMessage('fail', 'Validation failed: ' + responseArray.errors.value);
            updateFieldOnSuccess($td, type, id, field);
        }
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
        $(".select_attribute, .select_proposal").prop("checked", true);
    } else {
        $(".select_attribute, .select_proposal").prop("checked", false);
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
    if ($('.select_attribute:checked').length > 0) {
        $('.mass-select').removeClass('hidden');
        if ($("#object-button").length) {
            $("#object-button").removeClass('last');
        } else {
            $('#create-button').removeClass('last');
        }
    } else {
        $('.mass-select').addClass('hidden');
        if ($("#object-button").length) {
            $("#object-button").addClass('last');
        } else {
            $('#create-button').addClass('last');
        }
    }
}

function listCheckboxesChecked() {
    if ($('.select:checked').length > 0)  {
        $('.mass-select').removeClass('hidden');
    } else {
        $('.mass-select').addClass('hidden')
    }
}

function listCheckboxesCheckedEventIndex() {
    // Show mass delete just when user has permission to delete at least one of selected event
    if ($('.select:checked[data-can-modify="1"]').length > 0) {
        $('.mass-delete').removeClass('hidden');
    } else {
        $('.mass-delete').addClass('hidden');
    }

    if ($('.select:checked').length > 0) {
        $('.mass-export').removeClass('hidden');
    } else {
        $('.mass-export').addClass('hidden');
    }
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
    $(".select:checked").each(function() {
        if ($(this).data('can-modify')) {
            var temp = $(this).data("id");
            if (temp != null) {
                selected.push(temp);
            }
        }
    });
    deleteEventPopup(JSON.stringify(selected));
}

function deleteEventPopup(eventId) {
    $.get(baseurl + "/events/delete/" + eventId, openConfirmation).fail(xhrFailCallback);
}

function multiSelectExportEvents() {
    var selected = [];
    $(".select:checked").each(function() {
        var temp = $(this).data("id");
        if (temp != null) {
            selected.push(temp);
        }
    });
    openGenericModal(baseurl + "/events/restSearchExport/" + JSON.stringify(selected))
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
    $.get(baseurl + "/feeds/toggleSelected/" + on + "/" + cache + "/" + JSON.stringify(selected), openConfirmation).fail(xhrFailCallback);
}

function multiSelectToggleField(scope, action, fieldName, enabled, inputID) {
    var selected = [];
    $(".select:checked").each(function() {
        var temp = $(this).data("id");
        if (temp != null) {
            selected.push(temp);
        }
    });
    $.get(baseurl + "/" + scope + "/" + action + "/" + fieldName + "/" + enabled, function(data) {
        var $formData = $(data);
        $('body').append($formData)
        $formData.find(inputID).val(JSON.stringify(selected));
        $formData.find("form")[0].submit();
    }).fail(xhrFailCallback);
}

function multiSelectDeleteEventBlocklist(on, cache) {
    var selected = [];
    $(".select").each(function() {
        if ($(this).is(":checked")) {
            var temp = $(this).data("id");
            if (temp != null) {
                selected.push(temp);
            }
        }
    });
    $.get(baseurl + "/eventBlocklists/massDelete?ids=" + JSON.stringify(selected), openConfirmation).fail(xhrFailCallback);
}

function multiSelectAction(event_id, context) {
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
        $(".select_" + settings[context]["alias"] + ":checked").each(function() {
            selected.push($(this).data("id"));
        });
        $('#' + settings[context]["camelCase"] + 'Ids' + settings[context]["action"].ucfirst()).attr('value', JSON.stringify(selected));
        var formData = $('#' + settings[context]["action"] + '_selected').serialize();
        if (context == 'deleteAttributes') {
            var url = $('#delete_selected').attr('action');
        } else {
            var url = baseurl + "/" + settings[context]["controller"] + "/" + settings[context]["action"] + "Selected/" + event_id;
        }
        xhr({
            data: formData,
            type:"POST",
            url: url,
            success: function (data) {
                updateIndex(null, 'event');
                var result = handleGenericAjaxResponse(data);
                if (settings[context]["action"] != "discard" && result == true) {
                    eventUnpublish();
                }
            },
        });
    }
    return false;
}

function editSelectedAttributes(event) {
    var selectedAttributeIds = getSelected();
    var data = { selected_ids: selectedAttributeIds }
    simplePopup(baseurl + "/attributes/getMassEditForm/" + event, 'POST', data);
}

function addSelectedTaxonomies(taxonomy) {
    $.get(baseurl + "/taxonomies/taxonomyMassConfirmation/"+taxonomy, openConfirmation).fail(xhrFailCallback);
}

function proposeObjectsFromSelectedAttributes(clicked, event_id) {
    var selectedAttributeIds = getSelected();
    popoverPopup(clicked, event_id + '/' + selectedAttributeIds, 'objects', 'proposeObjectsFromAttributes');
}

function bulkAddRelationshipToSelectedAttributes(clicked, event_id) {
    var selectedAttributeIds = getSelected();
    var url = baseurl + '/objectReferences/bulkAdd/' + event_id + '/' + selectedAttributeIds
    openGenericModal(url)
}

function hideSelectedTags(taxonomy) {
	$.get(baseurl + "/taxonomies/taxonomyMassHide/"+taxonomy, openConfirmation).fail(xhrFailCallback);
}

function unhideSelectedTags(taxonomy) {
	$.get(baseurl + "/taxonomies/taxonomyMassUnhide/"+taxonomy, openConfirmation).fail(xhrFailCallback);
}

function getSelected() {
    var selected = [];
    $(".select_attribute:checked").each(function() {
        var test = $(this).data("id");
        selected.push(test);
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
        dataType: "html",
        cache: false,
        success: function (data) {
            $(".eventTagContainer").html(data);
        },
        url: baseurl + "/tags/showEventTag/" + id,
    });
}

function loadGalaxies(id, scope) {
    $.ajax({
        dataType:"html",
        cache: false,
        success: function (data) {
            if (scope === 'event') {
                $("#galaxies_div").html(data);
            } else if (scope === 'attribute') {
                $("#attribute_" + id + "_galaxy").html(data);
            }
        },
        url: baseurl + "/galaxies/showGalaxies/" + id + "/" + scope,
    });
}

function loadAttributeTags(attribute_id) {
    $.ajax({
        dataType: "html",
        cache: false,
        success: function (data) {
            $("[data-primary-id=" + attribute_id + "] .attributeTagContainer").html(data);
        },
        error: xhrFailCallback,
        url: baseurl + "/tags/showAttributeTag/" + attribute_id
    });
}

function removeObjectTagPopup(clicked, context, object, tag) {
    $.get(baseurl + "/" + context + "s/removeTag/" + object + '/' + tag, function(data) {
        openPopover(clicked, data);
    }).fail(xhrFailCallback);
}

function removeObjectTag(context, object, tag) {
    var formData = $('#PromptForm').serialize();
    xhr({
        data: formData,
        type:"POST",
        url: "/" + context.toLowerCase() + "s/removeTag/" + object + '/' + tag,
        success:function (data) {
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
    });
    return false;
}

function redirectAddObject(templateId, additionalData) {
    var eventId = additionalData['event_id'];
    window.location = baseurl + '/objects/add/' + eventId + '/' + templateId;
}

function openGenericModal(url, modalData, callback) {
    $.ajax({
        type: "get",
        url: url,
        success: function (data) {
            $('#genericModal').remove();
            var htmlData;
            if (modalData !== undefined) {
                var $modal = $('<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true"></div>');
                if (modalData.classes !== undefined) {
                    $modal.addClass(modalData.classes);
                }
                var $modalHeaderText = $('<h3 id="genericModalLabel"></h3>');
                if (modalData.header !== undefined) {
                    $modalHeaderText.text(modalData.header)
                }
                var $modalHeader = $('<div class="modal-header"></div>').append(
                    $('<button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>'),
                    $modalHeaderText
                );
                var $modalBody = $('<div class="modal-body"></div>').html(data);
                if (modalData.bodyStyle !== undefined) {
                    $modalBody.css(modalData.bodyStyle);
                }
                $modal.append(
                    $modalHeader,
                    $modalBody
                );
                htmlData = $modal[0].outerHTML;
            } else {
                htmlData = data;
            }
            $(document.body).append(htmlData);
            $('#genericModal').modal().on('shown', function() {
                if (callback !== undefined) {
                    callback();
                }
            });
        },
        error: xhrFailCallback,
    });
}

function openGenericModalPost(url, body) {
    $.ajax({
        data: body,
        type: "post",
        url: url,
        success: function (data) {
            $('#genericModal').remove();
            $('body').append(data);
            $('#genericModal').modal();
        },
        error: function (data, textStatus, errorThrown) {
            showMessage('fail', textStatus + ": " + errorThrown);
        }
    });
}

function submitPopoverForm(context_id, referer, update_context_id, modal, popover_dismiss_id_to_close) {
    var $form;
    var context = 'event';
    var contextNamingConvention = 'Attribute';
    var closePopover = true;
    switch (referer) {
        case 'addTextElement':
            context = 'template';
            contextNamingConvention = 'TemplateElementText';
            break;
        case 'editTextElement':
            context = 'template';
            context_id = update_context_id;
            contextNamingConvention = 'TemplateElementText';
            break;
        case 'addAttributeElement':
            context = 'template';
            contextNamingConvention = 'TemplateElementAttribute';
            break;
        case 'editAttributeElement':
            context = 'template';
            context_id = update_context_id;
            contextNamingConvention = 'TemplateElementAttribute';
            break;
        case 'addFileElement':
            context = 'template';
            contextNamingConvention = 'TemplateElementFile';
            break;
        case 'editFileElement':
            context = 'template';
            context_id = update_context_id;
            contextNamingConvention = 'TemplateElementFile';
            break;
        case 'addSighting':
            closePopover = false;
            break;
    }
    var $submitButton = $("#submitButton");
    if ($submitButton.parent().hasClass('modal-footer')) {
        $form = $submitButton.parent().parent().find('.modal-body form');
    } else {
        $form = $submitButton.closest("form");
    }
    var url = $form.attr('action');
    // Prepend URL with baseurl if URL is relative
    if (!url.startsWith('http')) {
        url = baseurl + url;
    }
    $.ajax({
        beforeSend: function () {
            if (modal) {
                if (closePopover) {
                    $('#genericModal').modal('hide');
                }
            } else {
                if (closePopover) {
                    $("#gray_out").fadeOut();
                    $("#popover_form").fadeOut();
                    if (popover_dismiss_id_to_close !== undefined) {
                        $('[data-dismissid="' + popover_dismiss_id_to_close + '"]').popover('destroy');
                    }
                    $(".loading").show();
                }
            }
        },
        data: $form.serialize(),
        success: function (data) {
            if (closePopover) {
                if (modal) {
                    handleAjaxModalResponse(data, context_id, url, referer, context, contextNamingConvention);
                } else {
                    handleAjaxPopoverResponse(data, context_id, url, referer, context, contextNamingConvention);
                }
            }
            if (referer === 'addSighting') {
                updateIndex(update_context_id, 'event');
                $.get(baseurl + "/sightings/listSightings/" + id + "/attribute", function(data) {
                    $("#sightingsData").html(data);
                }).fail(xhrFailCallback);
                $('.sightingsToggle').removeClass('btn-primary').addClass('btn-inverse');
                $('#sightingsListAllToggle').removeClass('btn-inverse').addClass('btn-primary');
            }
            if (referer === 'addEventReport' && typeof window.reloadEventReportTable === 'function') {
                reloadEventReportTable()
                eventUnpublish()
            }
            if (
                (
                    context === 'event' &&
                    (referer === 'add' || referer === 'massEdit' || referer === 'replaceAttributes' || referer === 'addObjectReference' || referer === 'quickAddAttributeForm')
                )
            ){
                eventUnpublish();
            }
        },
        error: xhrFailCallback,
        complete: function () {
            $(".loading").hide();
        },
        type: "post",
        url: url,
    });
    return false;
}

function handleAjaxModalResponse(response, context_id, url, referer, context, contextNamingConvention) {
    var responseArray = response;
    if (responseArray.saved) {
        updateIndex(context_id, context);
        if (responseArray.success) {
            var message = "message" in responseArray ? responseArray.message : responseArray.success;
            showMessage("success", message);
        } else if (responseArray.errors) {
            showMessage("fail", responseArray.errors);
        }
    } else {
        if (responseArray.errors && typeof responseArray.errors === 'string') {
            var fullErrors = "full_errors" in responseArray ? responseArray.full_errors : '';
            showMessage("fail", responseArray.errors, fullErrors);
        } else {
            var savedArray = saveValuesForPersistance();
            $.ajax({
                dataType: "html",
                success: function (data) {
                    $('#genericModal').remove();
                    $('body').append(data);
                    $('#genericModal').modal();
                    handleValidationErrors(responseArray.errors, context, contextNamingConvention);
                    recoverValuesFromPersistance(savedArray);
                },
                error: xhrFailCallback,
                complete: function () {
                    $(".loading").hide();
                },
                url: url
            });
        }
    }
}

function handleAjaxPopoverResponse(response, context_id, url, referer, context, contextNamingConvention) {
    responseArray = response;
    var result = "fail";
    if (responseArray.saved) {
        var callback = function() {
            // Scroll to edited object after index is updated
            if (referer === 'quickAddAttributeForm') {
                scrollToElementIfNotVisible($("#Object_" + context_id + "_tr"));
            }
        }
        updateIndex(context_id, context, callback);
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
            dataType: "html",
            success: function (data, textStatus) {
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
            url: url
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
        var $element = $("#" + contextNamingConvention + elementName);
        $element.parent().addClass("error");
        $element.parent().append("<div class=\"error-message\">" + responseArray[k] + "</div>");
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
    xhr({
        dataType:"html",
        success:function (data) {
            $("#histogram").html(data);
        },
        url: "/users/histogram/" + selected,
    });
}

function showMessage(success, message, fullError) {
    var duration = 1000 + (message.length * 40);

    if (message.indexOf("$flashErrorMessage") >= 0) {
        var flashMessageLink = '<a href="#" class="bold" data-content="' + escapeHtml(fullError) + '" data-html="true" onclick="event.preventDefault();$(this).popover(\'show\')">here</a>';
        message = message.replace("$flashErrorMessage", flashMessageLink);
        duration = 5000;
    }

    $("#ajax_" + success).html(message);
    $("#ajax_" + success + "_container").fadeIn("slow").delay(duration).fadeOut("slow");
}

function cancelPopoverForm(id) {
    $("#gray_out").fadeOut();
    $("#popover_form_large").fadeOut();
    $("#screenshot_box").fadeOut(400, function() {
        $(this).remove();
    });
    $('.tooltip').remove()
    $("#popover_box")
        .fadeOut()
        .removeAttr('style') // remove all inline styles
        .empty(); // remove all child elements
    $("#confirmation_box").fadeOut();
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

function appendTemplateTag(selected_id)     {
    xhr({
        dataType: "html",
        success: function (data) {
            $("#tags").append(data);
        },
        url: "/tags/viewTag/" + selected_id,
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
        success:function (data) {
            handleGenericAjaxResponse(data);
        },
        error: xhrFailCallback,
        type:"post",
        cache: false,
        url: baseurl + "/templates/saveElementSorting/",
    });
}

function templateAddElementClicked(id) {
    simplePopup(baseurl + "/template_elements/templateElementAddChoices/" + id);
}

function templateAddElement(type, id) {
    simplePopup(baseurl + "/template_elements/add/" + type + "/" + id);
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

function openConfirmation(data) {
    var $box = $("#confirmation_box");
    $box.html(data);
    openPopup($box);
}

function openPopup(id, adjust_layout, callback) {
    var $id = $(id);
    adjust_layout = adjust_layout === undefined ? true : adjust_layout;
    if (adjust_layout) {
        $id.css({'top': '', 'height': ''}).removeClass('vertical-scroll'); // reset inline values

        var window_height = $(window).height();
        var popup_height = $id.height();
        if (window_height < popup_height) {
            $id.css("top", 50);
            $id.css("height", window_height - 50);
            $id.addClass('vertical-scroll');
        } else {
            if (window_height > (300 + popup_height)) {
                var top_offset = ((window_height - popup_height) / 2) - 125;
            } else {
                var top_offset = (window_height - popup_height) / 2;
            }
            $id.css("top", top_offset);
        }
    }
    $("#gray_out").fadeIn();
    $id.fadeIn(400, function() {
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
    var closeButtonHtml = '<button class="close" style="margin-left: 5px;">×</button>';

    if (!$clicked.data('popover')) { // true when popover was already created defined
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
        .on('shown.bs.popover', function() {
            var $this = $(this); // should be the same as $clicked
            var $popover = $this.data("popover").tip(); // should be the content of popover
            var title = $this.attr('title');
            title = title === "" ? $this.attr('data-original-title') : title;

            $popover.on("click", ".close", function () {
                $this.popover("hide");
            });

            if (title === "") {
                title = "&nbsp;";
                // adjust popover position (title was empty)
                var top = $popover.offset().top;
                $popover.css('top', (top-17) + 'px');
            }
            var popoverTitle = $popover.find('h3.popover-title');
            popoverTitle.html(title + closeButtonHtml);
            if (callback !== undefined) {
                callback($popover);
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
        } else if (data !== undefined) {
            $clicked.popover('show');
        }

    } else if (data !== undefined) {
        $clicked.popover('show');
    }
    var popover = $clicked.data('popover');

    if (data !== undefined && popover.options.content !== data) {
        popover.options.content = data;
        $clicked.popover('show');
    }
    return popover;
}

function getMatrixPopup(scope, scope_id, galaxy_id) {
    cancelPopoverForm();
    getPopup(scope_id + '/' + galaxy_id + '/' + scope, 'events', 'viewGalaxyMatrix', '', '#popover_matrix');
}

function getPopup(id, context, target, admin, popupType) {
    $("#gray_out").fadeIn();
    var url = baseurl;
    if (typeof admin !== 'undefined' && admin != '') url+= "/admin";
    if (context != '') {
        url += "/" + context;
    }
    if (target != '') url += "/" + target;
    if (id != '') url += "/" + id;
    if (popupType == '' || typeof popupType == 'undefined') popupType = '#popover_form';
    $.ajax({
        beforeSend: function () {
            $(".loading").show();
        },
        dataType:"html",
        cache: false,
        success:function (data, textStatus) {
            $(".loading").hide();
            $(popupType).html(data);
            openPopup(popupType, false);
        },
        error:function(xhr) {
            $(".loading").hide();
            $("#gray_out").fadeOut();
            xhrFailCallback(xhr);
        },
        url: url
    });
}

// Same as getPopup function but create a popover to populate first
// DEPRECATED
function popoverPopup(clicked, id, context, target, admin) {
    var url = baseurl;
    if (typeof admin !== 'undefined' && admin != '') url+= "/admin";
    if (context != '') {
        url += "/" + context;
    }
    if (target != '') url += "/" + target;
    if (id != '') url += "/" + id;
    popoverPopupNew(clicked, url);
}

function popoverPopupNew(clicked, url) {
    var $clicked = $(clicked);
    var popover = openPopover($clicked, undefined);

    // actual request
    $.ajax({
        dataType: "html",
        cache: false,
        success: function (data) {
            popover.options.content = data;
            $clicked.popover('show');
        },
        error: function(jqXHR) {
            var errorJSON = '';
            try {
                errorJSON = JSON.parse(jqXHR.responseText);
                errorJSON = errorJSON['errors'];
                if (errorJSON === undefined) {
                    errorJSON = '';
                }
            } catch (SyntaxError) {
                // no error provided
                if (jqXHR.status === 401) {
                    errorJSON = 'Unauthorized. Please reload page to log again.';
                }
            }
            var errorText = '<div class="alert alert-error" style="margin-bottom: 3px;">Something went wrong - the queried function returned an exception. Contact your administrator for further details (the exception has been logged).</div>';
            if (errorJSON !== '') {
                errorText += '<div class="well"><strong>Returned error:</strong> ' + $('<span/>').text(errorJSON).html() + '</div>';
            }
            popover.options.content = errorText;
            $clicked.popover('show');
        },
        url: url
    });
}

function confirmClusterDetach(clicked, target_type, target_id) {
    popoverConfirm(clicked, undefined, undefined, function (data) {
        handleGenericAjaxResponse(data);
        if (target_type === "event") {
            loadGalaxies(target_id, 'event');
        } else if (target_type === "attribute") {
            loadGalaxies(target_id, 'attribute');
        } else {
            location.reload();
        }
    })
}

// create a confirm popover on the clicked html node.
function popoverConfirm(clicked, message, placement, callback) {
    event.preventDefault();

    var $clicked = $(clicked);
    var popoverContent = '<div>';
        popoverContent += message === undefined ? '' : '<p>' + message + '</p>';
        popoverContent += '<button id="popoverConfirmOK" class="btn btn-primary" style="margin-right: 5px;">Yes</button>';
        popoverContent += '<button class="btn btn-inverse" style="float: right;" onclick="cancelPrompt()">Cancel</button>';
    popoverContent += '</div>';
    openPopover($clicked, popoverContent, undefined, placement);

    $("#popoverConfirmOK")
    .focus()
    .bind("keydown", function(e) {
        if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
            $(this).click();
        } else if (e.keyCode == 27) { // ESC
            $clicked.popover('destroy');
        }
    }).click(function() {
        var href = $clicked.attr("href");
        // Load form to get new token
        fetchFormDataAjax(href, function (form) {
            var $formContainer = $(form);
            var $form = $formContainer.is('form') ? $formContainer : $formContainer.find('form');
            $clicked.popover('destroy');
            xhr({
                data: $form.serialize(),
                success: function (data) {
                    if (callback !== undefined) {
                        callback(data);
                    } else {
                        location.reload();
                    }
                },
                complete: function() {
                    $(".loading").hide();
                    $("#popover_form").fadeOut();
                    $("#gray_out").fadeOut();
                },
                type: "post",
                url: $form.attr('action')
            });
        })
    });
}

function simplePopup(url, requestType, data) {
    requestType = requestType === undefined ? 'GET' : requestType
    data = data === undefined ? [] : data
    $("#gray_out").fadeIn();
    xhr({
        dataType: "html",
        success: function (data) {
            var $popover = $("#popover_form");
            $popover.html(data);
            openPopup($popover);
        },
        error: function(xhr) {
            $("#gray_out").fadeOut();
            xhrFailCallback(xhr);
        },
        url: url,
        type: requestType,
        data: data
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

function openModal(heading, body, footer, modal_option, css_container, css_body, class_container) {
    var modal_id = 'dynamic_modal_' + new Date().getTime();
    var modal_html = '<div id="' + modal_id + '" class="modal hide fade ' + (class_container !== undefined ? class_container : '') + '" style="' + (css_container !== undefined ? css_container : '') + '" tabindex="-1" role="dialog" aria-hidden="true">';
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
        url: baseurl + "/templates/deleteTemporaryFile/" + tmp_name,
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

        if (filtering.timestamp.from != null) {
            var text = "";
            if (filtering.timestamp.from != "") text = "From: " + $('<span>').text(filtering.timestamp.from).html();
            if (filtering.timestamp.until != "") {
                if (text != "") text += " ";
                text += "Until: " + $('<span>').text(filtering.timestamp.until).html();
            }
        }
        $('#value_timestamp').html(text);

        if (filtering.publishtimestamp.from != null) {
            var text = "";
            if (filtering.publishtimestamp.from != "") text = "From: " + $('<span>').text(filtering.publishtimestamp.from).html();
            if (filtering.publishtimestamp.until != "") {
                if (text != "") text += " ";
                text += "Until: " + $('<span>').text(filtering.publishtimestamp.until).html();
            }
        }
        $('#value_publishtimestamp').html(text);

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
        passedArgs["searchall"] = encodeURIComponent($('#quickFilterField').val().trim());
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
    for (var k in dataFields) {
        if (k in passedArgsArray) {
            delete(passedArgsArray[k]);
        } else {
            passedArgsArray[k] = dataFields[k];
        }
    }
    var url = here;
    for (var key in passedArgsArray) {
        url += "/" + key + ":" + passedArgsArray[key];
    }
    window.location.href = url;
}

function cancelSearch() {
    $('#quickFilterField').val('');
    $('#quickFilterButton').click();
}

// Deprecated, when possible use runIndexQuickFilterFixed that is cleaner
function runIndexQuickFilter(preserveParams, url, target) {
    if (typeof passedArgsArray === "undefined") {
        var passedArgsArray = [];
    }
    var searchKey = 'searchall';
    var $quickFilterField = $('#quickFilterField');
    if ($quickFilterField.length > 0) {
        if ($quickFilterField.data('searchkey')) {
            searchKey = $('#quickFilterField').data('searchkey');
        }
        var value = $quickFilterField.val().trim();
        if (value.length > 0){
            passedArgsArray[searchKey] = encodeURIComponent(value);
        }
    }
    if (typeof url === "undefined") {
        url = here;
    }
    if (typeof preserveParams === "string") {
        preserveParams = String(preserveParams);
        if (!preserveParams.startsWith('/')) {
            preserveParams = '/' + preserveParams;
        }
        url += preserveParams;
    } else if (typeof preserveParams === "object") {
        for (var key in preserveParams) {
            if (typeof key == 'number') {
                url += "/" + preserveParams[key];
            } else if (key !== 'page') {
                if (key !== searchKey || !(searchKey in passedArgsArray)) {
                    url += "/" + key + ":" + preserveParams[key];
                }
            }
        }
    }
    for (var key in passedArgsArray) {
        if (typeof key == 'number') {
            url += "/" + passedArgsArray[key];
        } else if (key !== 'page') {
            url += "/" + key + ":" + passedArgsArray[key];
        }
    }
    if (target !== undefined) {
        $.ajax({
            beforeSend: function () {
                $(".loading").show();
            },
            success: function (data) {
                $(target).html(data);
            },
            error: function() {
                showMessage('fail', 'Could not fetch the requested data.');
            },
            complete: function() {
                $(".loading").hide();
            },
            type: "get",
            url: url
        });
    } else {
        window.location.href = url;
    }
}

/**
 * @param {object} preserveParams
 * @param {string} url
 * @param {string} [target]
 */
function runIndexQuickFilterFixed(preserveParams, url, target) {
    var $quickFilterField = $('#quickFilterField');
    var searchKey;
    if ($quickFilterField.data('searchkey')) {
        searchKey = $quickFilterField.data('searchkey');
    } else {
        searchKey = 'searchall';
    }
    if ($quickFilterField.val().trim().length > 0) {
        preserveParams[searchKey] = encodeURIComponent($quickFilterField.val().trim()).replace('%20', '+');
    } else {
        delete preserveParams[searchKey]
    }
    for (var key in preserveParams) {
        if (!isNaN(key)) {
            url += "/" + preserveParams[key];
        } else if (key !== 'page') {
            url += "/" + key + ":" + preserveParams[key];
        }
    }

    if (target !== undefined) {
        xhr({
            success: function (data) {
                $(target).html(data);
            },
            error: function() {
                showMessage('fail', 'Could not fetch the requested data.');
            },
            type: "get",
            url: url
        });
    } else {
        window.location.href = url;
    }
}

function executeFilter(passedArgs, url) {
    for (var key in passedArgs) url += "/" + key + ":" + passedArgs[key];
    window.location.href=url;
}

function quickFilterTaxonomy(taxonomy_id, passedArgs) {
    var url = baseurl + "/taxonomies/view/" + taxonomy_id + "/filter:" + encodeURIComponent($('#quickFilterField').val());
    window.location.href=url;
}

function quickFilterRemoteEvents(passedArgs, id) {
    passedArgs["searchall"] = $('#quickFilterField').val();
    var url = baseurl + "/servers/previewIndex/" + id;
    for (var key in passedArgs) {
        url += "/" + key + ":" + encodeURIComponent(passedArgs[key]);
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
        if (filtering.timestamp.from) {
            if (text != "") text += "/";
            text += "searchTimestamp:" + filtering.timestamp.from;
        }
        if (filtering.timestamp.until) {
            if (text != "") text += "/";
            text += "searchTimestamp:" + filtering.timestamp.until;
        }
        if (filtering.publishtimestamp.from) {
            if (text != "") text += "/";
            text += "searchPublishTimestamp:" + filtering.publishtimestamp.from;
        }
        if (filtering.publishtimestamp.until) {
            if (text != "") text += "/";
            text += "searchPublishTimestamp:" + filtering.publishtimestamp.until;
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
    var text = "";
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
        if (param.data.param1 == "date" || param.data.param1 == "timestamp" || param.data.param1 == "publishtimestamp") {
            var val1 = encodeURIComponent($('#EventSearch' + param.data.param1 + 'from').val());
            var val2 = encodeURIComponent($('#EventSearch' + param.data.param1 + 'until').val());
            if (val1 != "") filtering[param.data.param1].from = val1;
            if (val2 != "") filtering[param.data.param1].until = val2;
        } else if (param.data.param1 == "published") {
            var value = encodeURIComponent($('#EventSearchpublished').val());
            if (value != "") filtering.published = value;
        } else if (param.data.param1 == "hasproposal") {
            var value = encodeURIComponent($('#EventSearchhasproposal').val());
            if (value != "") filtering.hasproposal = value;
        } else {
            var value = encodeURIComponent($('#EventSearch' + param.data.param1).val());
            var operator = operators[encodeURIComponent($('#EventSearchbool').val())];
            if (value != "" && filtering[param.data.param1][operator].indexOf(value) < 0) filtering[param.data.param1][operator].push(value);
        }
    } else if (filterContext == 'user') {
        if (differentFilters.indexOf(param.data.param1) != -1) {
            var value = encodeURIComponent($('#UserSearch' + param.data.param1).val());
            if (value != "") filtering[param.data.param1] = value;
        } else {
            var value = encodeURIComponent($('#UserSearch' + param.data.param1).val());
            var operator = operators[encodeURIComponent($('#UserSearchbool').val())];
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
    if (fieldName === '#' + context + 'Searchdate' || fieldName === '#' + context + 'Searchtimestamp' || fieldName === '#' + context + 'Searchpublishtimestamp') {
        $(fieldName + 'from').show();
        $(fieldName + 'until').show();
    } else {
        if ($(fieldName + '_chosen').length) {
            $(fieldName + '_chosen').show();
        } else {
            $(fieldName).show();
        }
    }
    if (simpleFilters.indexOf(rule) != -1) {
        $('#' + context + 'Searchbool').show();
    } else $('#' + context + 'Searchbool').hide();

    $('#addRuleButton').show().unbind("click").click({param1: rule}, indexAddRule);
}

function indexFilterClearRow(field) {
    $('#value_' + field).html("");
    $('#row_' + field).hide();
    if (field == "date") {
        filtering.date.from = "";
        filtering.date.until = "";
    } else if (field == "timestamp") {
        filtering.timestamp.from = "";
        filtering.timestamp.until = "";
    } else if (field == "publishtimestamp") {
        filtering.publishtimestamp.from = "";
        filtering.publishtimestamp.until = "";
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
    xhr({
        dataType:"html",
        success: function (data) {
            $(fieldName + "_placeholder").html(data).show();
            $(fieldName + "_solid").hide();
            serverSettingsPostActivationScripts(fieldName, setting, id);
        },
        url: "/servers/serverSettingsEdit/" + setting + "/" + id,
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
    var subGroup = getSubGroupFromSetting(setting);
    var formData = $(name + '_field').closest("form").serialize();
    $.ajax({
        data: formData,
        cache: false,
        beforeSend: function () {
            $(".loading").show();
        },
        success: function (data) {
            if (!data.saved) {
                $(".loading").hide();
                showMessage('fail', data.errors);
                resetForms();
                $('.inline-field-placeholder').hide();
                return;
            }

            $.ajax({
                type: "get",
                url: baseurl + "/servers/serverSettingsReloadSetting/" + setting + "/" + id,
                success: function (data2) {
                    $('#' + subGroup + "_" + id + '_row').replaceWith(data2);
                    $(".loading").hide();
                },
                error: function() {
                    showMessage('fail', 'Could not refresh the table.');
                }
            });
        },
        error: function() {
            $(".loading").hide();
            showMessage('fail', 'Request failed for an unknown reason.');
            resetForms();
            $('.inline-field-placeholder').hide();
        },
        type: "post",
        url: baseurl + "/servers/serverSettingsEdit/" + setting + "/" + id + "/" + 1
    });
    $(name + '_field').unbind("keyup");
    $(name + '_form').unbind("focusout");
    return false;
}

function updateOrgCreateImageField(string) {
    string = encodeURIComponent(string);
    $.ajax({
        url: baseurl + '/img/orgs/' + string + '.png',
        type:'HEAD',
        error:
            function(){
                $('#logoDiv').html('No image uploaded for this identifier');
            },
        success:
            function(){
                $('#logoDiv').html('<img src="' + baseurl + '/img/orgs/' + string + '.png" style="width:24px;height:24px;"></img>');
            }
    });
}

function generateOrgUUID() {
    $.ajax({
        url: baseurl + '/admin/organisations/generateuuid.json',
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
        var $popovers = $('[data-toggle="popover"]');
        if (!$popovers.is(e.target)) {
            $popovers.popover('hide');
        }
    });
}

function changeFreetextImportFrom() {
    var $changeTo = $('#changeTo');
    $changeTo.empty();
    options[$('#changeFrom').val()].forEach(function(element) {
        $changeTo.append(new Option(element));
    });
}

function changeFreetextImportCommentExecute() {
    $('.freetextCommentField').val($('#changeComments').val());
}

function changeFreetextImportExecute() {
    var from = $('#changeFrom').val();
    var to = $('#changeTo').val();
    $('.typeToggle').each(function() {
        if ($(this).val() === from) {
            if (selectContainsOption("#" + $(this).attr('id'), to)) {
                $(this).val(to);
            }
        }
    });
}

function selectContainsOption(selectid, value) {
    var exists = false;
    $(selectid + ' option').each(function(){
        if (this.value === value) {
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

function importChoiceSelect(url, ajax) {
    if (ajax == 'false') {
        document.location.href = url;
    } else {
        simplePopup(url);
    }
}

function freetextSerializeAttributes() {
    var attributeArray = [];
    $('.freetext_row').each(function() {
        var i = $(this).data('row');
        if ($('#Attribute' + i + 'Save').val() == 1) {
            attributeArray.push({
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
            })
        }
    });
    return attributeArray;
}

function freetextImportResultsSubmit(event_id, count) {
    var attributeArray = freetextSerializeAttributes();
    $("#MispAttributeJsonObject").val(JSON.stringify(attributeArray));
    var formData = $(".mainForm").serialize();
    xhr({
        type: "post",
        url: "/events/saveFreeText/" + event_id,
        data: formData,
        success: function () {
            window.location = baseurl + '/events/view/' + event_id;
        },
    });
}

function freetextRemoveRow(id, event_id) {
    $('.freetext_row[data-row=' + id + ']').hide();
    $('#Attribute' + id + 'Save').attr("value", "0");
    if ($(".freetext_row:visible").length == 0) {
        window.location = baseurl + "/events/" + event_id;
    } else {
        freetextPossibleObjectTemplates();
    }
}

function freetextCreateObject(objectId) {
    var attributeArray = freetextSerializeAttributes();
    $('#ObjectSelectedTemplateId').val(objectId);
    $('#ObjectAttributes').val(JSON.stringify(attributeArray));
    $('#ObjectFreeTextImportForm').submit();
}

function freetextPossibleObjectTemplates() {
    var allTypes = [];
    $('.freetext_row').each(function () {
        var rowId = $(this).data('row');
        if ($('#Attribute' + rowId + 'Save').val() === "1") {
            var type = $(this).find('.typeToggle').val();
            if (type === 'ip-src/ip-dst') {
                allTypes.push('ip-src', 'ip-dst');
            } else if (type === 'ip-src|port/ip-dst|port') {
                allTypes.push('ip-src|port', 'ip-dst|port');
            } else {
                allTypes.push(type);
            }
        }
    });

    if (allTypes.length < 2) {
        $('.createObject').hide();
        return;
    }

    $.ajax({
        dataType: "json",
        data: {"attributeTypes": allTypes},
        success: function (data) {
            if (data.length === 0) {
                $('.createObject').hide();
                return;
            }

            var $menu = $('.createObject ul');
            $menu.find('li').remove();

            $.each(data, function (i, template) {
                var a = document.createElement('a');
                a.href = '#';
                a.onclick = function () {
                    freetextCreateObject(template['id']);
                };
                a.textContent = template.name;
                a.title = template.description;

                var li = document.createElement('li');
                li.appendChild(a);

                $menu.append(li);
            });

            $('.createObject').show();
        },
        type: "post",
        url: baseurl + "/objectTemplates/possibleObjectTemplates",
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
        $(".MISPObject").each(function() {
            var object_uuid = $(this).find('.ObjectUUID').text();
            temp = {
                uuid: object_uuid,
                import_object: $(this).find('.ImportMISPObject')[0].checked,
                name: $(this).find('.ObjectName').text(),
                meta_category: $(this).find('.ObjectMetaCategory').text(),
                distribution: $(this).find('.ObjectDistribution').val(),
                sharing_group_id: $(this).find('.ObjectSharingGroup').val(),
                comment: $(this).find('.ObjectComment').val()
            }
            if (!temp['import_object']) {
                return true;
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
            if ($(this).has('.ObjectFirstSeen').length) {
                temp['first_seen'] = $(this).find('.ObjectFirstSeen').text();
            }
            if ($(this).has('.ObjectLastSeen').length) {
                temp['last_seen'] = $(this).find('.ObjectLastSeen').text();
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
                $(this).find('.ObjectAttribute').each(function() {
                    var attribute_type = $(this).find('.AttributeType').text();
                    var attribute = {
                        import_attribute: $(this).find('.ImportMISPObjectAttribute')[0].checked,
                        object_relation: $(this).find('.ObjectRelation').text(),
                        category: $(this).find('.AttributeCategory').text(),
                        type: attribute_type,
                        value: $(this).find('.AttributeValue').data('value'),
                        uuid: $(this).find('.AttributeUuid').text(),
                        to_ids: $(this).find('.AttributeToIds')[0].checked,
                        disable_correlation: $(this).find('.AttributeDisableCorrelation')[0].checked,
                        comment: $(this).find('.AttributeComment').val(),
                        distribution: $(this).find('.AttributeDistribution').val(),
                        sharing_group_id: $(this).find('.AttributeSharingGroup').val()
                    }
                    if (!attribute['import_attribute']) {
                        return true;
                    }
                    if (attribute['distribution'] != '4') {
                        attribute['sharing_group_id'] = '0';
                    }
                    if ($(this).find('.objectAttributeTagContainer').length) {
                        var tags = [];
                        $(this).find('.objectAttributeTag').each(function() {
                            tags.push({
                                name: $(this).attr('title'),
                                colour: rgb2hex($(this).css('background-color')),
                                local: $(this).data('local'),
                            });
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
        $('.MISPAttribute').each(function() {
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
                import_attribute: $(this).find('.ImportMISPAttribute')[0].checked,
                category: category_value,
                type: type_value,
                value: $(this).find('.AttributeValue').data('value'),
                uuid: $(this).find('.AttributeUuid').text(),
                to_ids: $(this).find('.AttributeToIds')[0].checked,
                disable_correlation: $(this).find('.AttributeDisableCorrelation')[0].checked,
                comment: $(this).find('.AttributeComment').val(),
                distribution: $(this).find('.AttributeDistribution').val(),
                sharing_group_id: $(this).find('.AttributeSharingGroup').val()
            }
            if (!temp['import_attribute']) {
                return true;
            }
            if (temp['distribution'] != '4') {
                temp['sharing_group_id'] = '0';
            }
            if ($(this).find('.attributeTagContainer').length) {
                var tags = [];
                $(this).find('.attributeTag').each(function() {
                    tags.push({
                        name: $(this).attr('title'),
                        colour: rgb2hex($(this).css('background-color')),
                        local: $(this).data('local'),
                    });
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
    if ($('.MISPEventReport').length) {
        var reports = [];
        $('.MISPEventReport').each(function() {
            temp = {
                import_report: $(this).find('.ImportMISPEventReport')[0].checked,
                name: $(this).find('.EventReportName').text(),
                content: $(this).find('.EventReportContent').text(),
                uuid: $(this).find('.EventReportUUID').text(),
                distribution: $(this).find('.EventReportDistribution').val(),
                sharing_group_id: $(this).find('.EventReportSharingGroup').val()
            }
            if (temp['import_report']) {
                reports.push(temp);
            }
        });
        data_collected['EventReport'] = reports;
    }
    $("#EventJsonObject").val(JSON.stringify(data_collected));
    var formData = $('.mainForm').serialize();
    xhr({
        type: "post",
        url: "/events/handleModuleResults/" + id,
        data: formData,
        success: function () {
            window.location = baseurl + '/events/view/' + id;
        },
    });
}

function objectTemplateViewContent(context, id) {
    var url = "/objectTemplateElements/viewElements/" + id + "/" + context;
    xhr({
        url: url,
        type:'GET',
        error: function(){
            $('#ajaxContent').html('An error has occurred, please reload the page.');
        },
        success: function(response){
            $('#ajaxContent').html(response);
        },
    });

}

function organisationViewContent(context, id) {
    organisationViewButtonHighlight(context);
    var action;
    if (context === 'members') {
        action = "/admin/users/index/searchorg:";
    } else if (context === 'events') {
        action = "/events/index/searchorg:";
    } else if (context === 'sharing_groups') {
        action = "/sharing_groups/index/searchorg:";
    }
    xhr({
        url: action + id,
        type:'GET',
        error: function(){
            $('#ajaxContent').html('An error has occurred, please reload the page.');
        },
        success: function(response){
            $('#ajaxContent').html(response);
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
            html += '>';
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
        html += '>';
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
    $('#SharingGroupUuid').attr('value', jsonparsed.sharingGroup.uuid);
    $('#SharingGroupDescription').text(jsonparsed.sharingGroup.description);
}

function runOnDemandAction(element, url, target, postFormField) {
    var elementContainer = '#' + target;
    var type = 'GET';
    var data = '';
    if (postFormField !== '') {
        type = 'POST';
        data = $('#' + postFormField).val();
        data = {value: data}
    }
    $.ajax({
        url: url,
        type: type,
        data: data,
        beforeSend: function () {
            $(elementContainer).html('Running...');
        },
        error: function(response) {
            var result = JSON.parse(response.responseText);
            $(elementContainer).empty();
            $(elementContainer)
            .append(
                $('<div>')
                .attr('class', 'bold red')
                .text('Error ' + response.status + ':')
            )
            .append(
                $('<div>')
                .attr('class', 'bold')
                .text(result.errors)
            );
        },
        success: function(response) {
            var result = JSON.parse(response);
            $(elementContainer).empty();
            for (var key in result) {
                $(elementContainer).append(
                    $('<div>')
                    .append(
                        $('<span>')
                        .attr('class', 'bold')
                        .text(key + ': ')
                    ).append(
                        $('<span>')
                        .attr('class', 'bold blue')
                        .text(result[key])
                    )
                );
            }
        }
    })
}

function getRemoteSyncUser(id) {
    var resultContainer = $("#sync_user_test_" + id);
    $.ajax({
        url: baseurl + '/servers/getRemoteUser/' + id,
        type: 'GET',
        beforeSend: function () {
            resultContainer.text('Running test...');
        },
        error: function() {
            resultContainer.html('<span class="red bold">Internal error</span>');
        },
        success: function(response) {
            resultContainer.empty();
            if (typeof response !== 'object') {
                resultContainer.html('<span class="red bold">Internal error</span>');
            } else if ("error" in response) {
                resultContainer.append(
                    $('<span>')
                        .attr('class', 'red bold')
                        .text('Error')
                ).append(
                    $('<span>')
                        .text(': #' + response.error)
                );
            } else {
                Object.keys(response).forEach(function(key) {
                    var value = response[key];
                    resultContainer.append(
                        $('<span>')
                        .attr('class', 'blue bold')
                        .text(key)
                    ).append(
                        $('<span>')
                        .text(': ' + value)
                    ).append(
                        $('<br>')
                    );
                });
            }
        }
    });
}

function testConnection(id) {
    $.ajax({
        url: baseurl + '/servers/testConnection/' + id,
        type: 'GET',
        beforeSend: function () {
            $("#connection_test_" + id).html('Running test...');
        },
        error: function(){
            $("#connection_test_" + id).html('<span class="red bold">Internal error</span>');
        },
        success: function(result) {
            function line(name, value, valid) {
                var $value = $('<span></span>').text(value);
                if (valid === true) {
                    $value.addClass('green');
                } else if (valid === false) {
                    $value.addClass('red');
                } else if (valid) {
                    $value.addClass(valid);
                }
                return $('<div></div>').text(name + ': ').append($value).html() + '<br>';
            }

            var html = '';

            if (result.client_certificate) {
                var cert = result.client_certificate;
                html += '<span class="bold">Client certificate:</span><br>';
                if (cert.error) {
                    html += '<span class="red bold">Error: ' + cert.error + '</span><br>';
                } else {
                    html += line("Subject", cert.subject);
                    html += line("Issuer", cert.issuer);
                    html += line("Serial number", cert.serial_number);
                    html += line("Valid from", cert.valid_from, cert.valid_from_ok);
                    html += line("Valid to", cert.valid_to, cert.valid_to_ok);
                    html += line("Public key", cert.public_key_type + ' (' + cert.public_key_size + ' bits)', cert.public_key_size_ok);
                }
                html += "<br>";
            }

            switch (result.status) {
            case 1:
                var status_message = "OK";
                var compatibility = "Compatible";
                var compatibility_colour = "green";
                var colours = {'local': 'class="green"', 'remote': 'class="green"', 'status': 'class="green"'};
                var issue_colour = "red";
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
                var post_result;
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
                html += line('Local version', result.local_version, colours.local);
                html += line('Remote version', result.version, colours.remote);
                html += line('Status', status_message, colours.status);
                html += line('Compatibility', compatibility, compatibility_colour);
                html += line('POST test', post_result, post_colour);
                break;
            case 2:
                html += '<span class="red bold" title="There seems to be a connection issue. Make sure that the entered URL is correct and that the certificates are in order.">Server unreachable</span>';
                break;
            case 3:
                html += '<span class="red bold" title="The server returned an unexpected result. Make sure that the provided URL (or certificate if it applies) are correct.">Unexpected error</span>';
                break;
            case 4:
                html += '<span class="red bold" title="Authentication failed due to incorrect authentication key or insufficient privileges on the remote instance.">Authentication failed</span>';
                break;
            case 5:
                html += '<span class="red bold" title="Authentication failed because the sync user is expected to change passwords. Log into the remote MISP to rectify this.">Password change required</span>';
                break;
            case 6:
                html += '<span class="red bold" title="Authentication failed because the sync user on the remote has not accepted the terms of use. Log into the remote MISP to rectify this.">Terms not accepted</span>';
                break;
            case 7:
                html += '<span class="orange bold" title="The user account on the remote instance is not a sync user.">Remote user not a sync user, only pulling events is available.</span>';
                break;
            case 8:
                html += '<span class="orange bold" title="The user account on the remote instance is only a sightings user.">Remote user not a sync user, only pulling events is available. Pushing availale for sightings only</span>';
                break;
            }

            $("#connection_test_" + id).html(html);
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

function gpgSelect(fingerprint) {
    $("#popover_form").fadeOut();
    $("#gray_out").fadeOut();
    xhr({
        type: "get",
        url: "/users/fetchGpgKey/" + fingerprint,
        success: function (data) {
            $("#UserGpgkey").val(data);
            showMessage('success', "Key found!");
        },
    });
}

function lookupPGPKey() {
    var email = $('#UserEmail').val();
    simplePopup(baseurl + "/users/searchGpgKey/" + email);
}

function zeroMQServerAction(action) {
    xhr({
        type: "get",
        url: "/servers/" + action + "ZeroMQServer/",
        success: function (data) {
            if (action !== 'status') {
                window.location.reload();
            } else {
                openConfirmation(data);
            }
        }
    });
}

function convertServerFilterRules(rules) {
    validOptions.forEach(function (type) {
        container = "#"+ modelContext + type.ucfirst() + "Rules";
        if ($(container).val() != '' && $(container).val() != '[]') {
            rules[type] = JSON.parse($(container).val());
        } else {
            if (type === 'pull') {
                rules[type] = {"tags": {"OR": [], "NOT": []}, "orgs": {"OR": [], "NOT": []}, "type_attributes": {"NOT": []}, "type_objects": {"NOT": []}, "url_params": ""}
            } else {
                rules[type] = {"tags": {"OR": [], "NOT": []}, "orgs": {"OR": [], "NOT": []}}
            }
        };
    });
    serverRuleUpdate();
    return rules;
}

function serverRuleUpdate() {
    var statusOptions = ["OR", "NOT"];
    validOptions.forEach(function(type) {
        validFields.forEach(function(field) {
            var indexedList = {};
            if (type === 'push' || field == 'type_objects') {
                if (window[field] !== undefined) {
                    window[field].forEach(function(item) {
                        indexedList[item.id] = item.name;
                    });
                }
            }
            statusOptions.forEach(function(status) {
                if (rules[type][field] !== undefined && rules[type][field][status] !== undefined) {
                    if (rules[type][field][status].length > 0) {
                        $('#' + type + '_' + field + '_' + status).show();
                        var t = '';
                        rules[type][field][status].forEach(function(item) {
                            if (t.length > 0) t += ', ';
                            if (type === 'pull') {
                                if (indexedList[item] !== undefined) {
                                    t += indexedList[item];
                                } else {
                                    t += item;
                                }
                            } else {
                                t += indexedList[item] !== undefined ? indexedList[item] : item;
                            }
                        });
                        $('#' + type + '_' + field + '_' + status + '_text').text(t);
                    } else {
                        $('#' + type + '_' + field + '_' + status).hide();
                    }
                }
            });
        });
        if (type === 'pull') {
            if (rules[type]['url_params']) {
                $("#pull_url_params").show();
                $("#pull_url_params_text").text(rules[type]['url_params']);
            } else {
                $("#pull_url_params").hide();
            }
        }
    });
    serverRuleGenerateJSON();
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

function serverRulesUpdateState(context) {
    var $rootContainer = $('.server-rule-container-' + context)
    validFields.forEach(function(field) {
        var $fieldContainer = $rootContainer.find('.scope-' + field)
        rules[context][field] = $fieldContainer.data('rules')
    })
    if (context === 'pull') {
        rules[context]["url_params"] = $rootContainer.find('textarea#urlParams').val();
    }
    serverRuleUpdate();
}

function syncUserSelected() {
    if ($('#UserRoleId :selected').val() in syncRoles) {
        $('#syncServers').show();
    } else {
        $('#syncServers').hide();
    }
}

function eventIndexColumnsToggle(columnName) {
    xhr({
        url: "/userSettings/eventIndexColumnToggle/" + columnName,
        method: "post",
        success: function () {
            window.location.reload(); // update page
        }
    });
}

// Find object or attribute by UUID on current page
function findObjectByUuid(uuid) {
    var $tr = null;
    $('#attributeList tr').each(function () {
        var trId = $(this).attr('id');
        if (trId && (trId.startsWith("Object") || trId.startsWith("Attribute") || trId.startsWith('proposal'))) {
            var objectUuid = $(this).data('uuid');
            if (objectUuid === uuid) {
                $tr = $(this);
                return false;
            }
        }
    });
    return $tr;
}

function focusObjectByUuid(uuid) {
    var $tr = findObjectByUuid(uuid);
    if (!$tr) {
        return false;
    }

    $([document.documentElement, document.body]).animate({
        scrollTop: $tr.offset().top - 45, // 42px is #topBar size, so make little bit more space
    }, 1000, null, function () {
        $tr.fadeTo(100, 0.3, function () { // blink active row
            $(this).fadeTo(500, 1.0);
        });
        $tr.focus();
    });
    return true;
}

function pivotObjectReferences(url, uuid) {
    if (focusObjectByUuid(uuid)) {
        return; // object is on the same page, we don't need to reload page
    }
    fetchAttributes(currentUri, {"focus": uuid});
}

function scrollToElementIfNotVisible($el) {
    var isInViewport = function($el) {
        var elementTop = $el.offset().top;
        var elementBottom = elementTop + $el.outerHeight();

        var viewportTop = $(window).scrollTop();
        var viewportBottom = viewportTop + $(window).height();

        return elementBottom > viewportTop && elementTop < viewportBottom;
    };

    if ($el.length && !isInViewport($el)) {
        $([document.documentElement, document.body]).animate({
            scrollTop: $el.offset().top - 45, // 42px is #topBar size, so make little bit more space
        });
    }
}

// Attribute filtering
function filterAttributes(filter) {
    var data;
    if (filter === 'value') {
        filter = $('#quickFilterField').val().trim();
        data = {"searchFor": filter}
    } else if (filter === 'all') {
        $('#quickFilterField').val(''); // clear input value
        data = {}
    } else {
        data = {"attributeFilter": filter}
        filter = $('#quickFilterField').val().trim();
        if (filter.length) {
            data["searchFor"] = filter;
        }
    }
    currentUri = resetPaginationParameters(currentUri)
    fetchAttributes(currentUri, data);
}

function toggleBoolFilter(param) {
    if (querybuilderTool === undefined) {
        triggerEventFilteringTool(true); // allows to fetch rules
    }
    var rules = querybuilderTool.getRules({ skip_empty: true, allow_invalid: true });
    var res = cleanRules(rules);

    if (res[param] !== undefined) {
        res[param] = res[param] == 0 ? 1 : 0;
    } else {
        res[param] = 1;
    }
    fetchAttributes(currentUri, res);
}

function resetPaginationParameters(currentUri) {
    var newUri = []
    currentUri.split('/').forEach(function(el) {
        if (
            el.startsWith('sort:') ||
            el.startsWith('direction:') ||
            el.startsWith('page:')
        ) {
            return
        }
        newUri.push(el)
    })
    return newUri.join('/')
}

function recursiveInject(result, rules) {
    if (rules.rules === undefined) { // add to result
        var field = rules.field;
        var value = rules.value;
        if (result.hasOwnProperty(field)) {
            if (Array.isArray(result[field])) {
                result[field].push(value);
            } else {
                result[field] = [result[field], value];
            }
        } else {
            result[field] = value;
        }
    }
    else if (Array.isArray(rules.rules)) {
        rules.rules.forEach(function(subrules) {
            recursiveInject(result, subrules);
        });
    }
}

function cleanRules(rules) {
    var res = {};
    recursiveInject(res, rules);
    // clean up invalid and unset
    Object.keys(res).forEach(function(k) {
        var v = res[k];
        if (v === undefined || v === '') {
            delete res[k];
        }
    });
    return res;
}

function performQuery(rules) {
    var res = cleanRules(rules);
    fetchAttributes(currentUri, res);
}

function setAttributeFilter(field, value) {
    if (querybuilderTool === undefined) {
        triggerEventFilteringTool(true); // allows to fetch rules
    }
    var rules = querybuilderTool.getRules({ skip_empty: true, allow_invalid: true });

    var found = false
    $.each(rules.rules, function (index, rule) {
        if (rule.field === field) {
            rule.value = value;
            found = true;
        }
    });
    if (!found) {
        rules.rules.push({"field": field, "value": value})
    }
    performQuery(rules);
}

function fetchAttributes(url, data) {
    var options = {
        type: "get",
        url: url,
        success: function (data) {
            $("#attributes_div").html(data);
        },
        error: function() {
            showMessage('fail', 'Something went wrong - could not fetch attributes.');
        }
    };
    if (data !== undefined) {
        // Cleanup URL from rules that has default value or are part of POST request
        for (var param in data) {
            if (defaultFilteringRules[param] == data[param]) {
                delete data[param];
            }
        }

        // delete url rules thats are part of default rules
        Object.keys(defaultFilteringRules).forEach(function (param) {
            if (url.indexOf(param) > -1) {
                var replace = '\/' + param + ".+/?";
                var re = new RegExp(replace,"i");
                url = url.replace(re, '');
            }
        });

        if (!$.isEmptyObject(data)) {
            options["type"] = "post";
            options["data"] = data;
        }
        options["url"] = url;
    }

    xhr(options);
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

// Hover enrichment
var hoverEnrichmentPopoverTimer;

function attributeHoverTitle(id, type) {
    return '<span>Lookup results:</span>\
		<i class="fa fa-search-plus useCursorPointer eventViewAttributePopup"\
				style="float: right;"\
				data-object-id="' + id + '"\
				data-object-type="' +  type + '">\
	</i>';
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

function showHoverEnrichmentPopover(type, id) {
    var html = ajaxResults["hover"][type + "_" + id];
    var element = $('#' + type + '_' + id + '_container');
    element.popover({
        title: attributeHoverTitle(id, type),
        content: html,
        placement: attributeHoverPlacement(element),
        html: true,
        trigger: 'manual',
        container: 'body'
    }).popover('show');
    if (currentPopover !== undefined && currentPopover !== '') {
        $('#' + currentPopover).popover('destroy');
    }
    currentPopover = type + '_' + id + '_container'
}

$(document.body).on('mouseenter', '.eventViewAttributeHover', function () {
    if (currentPopover !== undefined && currentPopover !== '') {
        $('#' + currentPopover).popover('destroy');
        currentPopover = '';
    }
    var type = $(this).attr('data-object-type');
    if (type==='attributes') type = 'Attribute'; // Type translation to expected input for further processing
    var id = $(this).attr('data-object-id');

    if (type + "_" + id in ajaxResults["hover"]) {
        showHoverEnrichmentPopover(type, id);
    } else {
        hoverEnrichmentPopoverTimer = setTimeout(function () {
                $.ajax({
                    success: function (html) {
                        ajaxResults["hover"][type + "_" + id] = html;
                        showHoverEnrichmentPopover(type, id);
                    },
                    cache: false,
                    url: baseurl + "/attributes/hoverEnrichment/" + id,
                });
            },
            500
        );
    }
}).on('mouseout', '.eventViewAttributeHover', function () {
    clearTimeout(hoverEnrichmentPopoverTimer);
});

function showEnrichmentPopover(type, id) {
    var $popoverBox = $('#popover_box');
    $popoverBox.empty();
    var enrichment_popover = ajaxResults["persistent"][type + "_" + id];
    enrichment_popover += '<div class="close-icon useCursorPointer popup-close-icon" onClick="closeScreenshot();"></div>';
    $popoverBox.html(enrichment_popover);
    $popoverBox.show();
    $("#gray_out").fadeIn();

    let maxWidth = ($(window).width() * 0.9 | 0);
    if (maxWidth > 1400) { // limit popover width to 1400 px
        maxWidth = 1400;
    }
    $popoverBox.css({
        'padding': '5px',
        'max-width': maxWidth + "px",
        'min-width': '700px',
        'height': ($(window).height() - 300 | 0) + "px",
        'background-color': 'white',
    });

    var left = ($(window).width() / 2) - ($popoverBox.width() / 2);
    $popoverBox.css({'left': left + 'px'});

    if (currentPopover !== undefined && currentPopover !== '') {
        $('#' + currentPopover).popover('destroy');
    }
}

// add the same as below for click popup
$(document).on("click", ".eventViewAttributePopup", function() {
    clearTimeout(hoverEnrichmentPopoverTimer); // stop potential popover loading

    var type = $(this).attr('data-object-type');
    var id = $(this).attr('data-object-id');
    if (!(type + "_" + id in ajaxResults["persistent"])) { // not in cache
        xhr({
            success: function (html) {
                ajaxResults["persistent"][type + "_" + id] = html; // save to cache
                showEnrichmentPopover(type, id);
            },
            url: "/attributes/hoverEnrichment/" + id + "/1",
        });
    } else {
        showEnrichmentPopover(type, id);
    }
});

$(document.body).on('click', function (e) {
  $('[data-toggle=popover]').each(function () {
    // hide any open popovers when the anywhere else in the body is clicked
    if (typeof currentPopover !== 'undefined' && currentPopover !== '') {
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
    xhr({
        type:"get",
        url: "/users/request_API/",
        success:function (data) {
            handleGenericAjaxResponse(data);
        },
        error:function() {
            showMessage('fail', 'Something went wrong - could not request API access.');
        }
    });
}

function checkSharingGroup(context) {
    var $sharingGroupSelect = $('#' + context + 'SharingGroupId');
    if ($('#' + context + 'Distribution').val() == 4) {
        $sharingGroupSelect.show();
        $sharingGroupSelect.closest("div").show();

        // For sharing group select with more than 10 items, use chosen
        if ($sharingGroupSelect.find('option').length > 10) {
            $sharingGroupSelect.chosen();
        }
    } else {
        $sharingGroupSelect.hide();
        $sharingGroupSelect.closest("div").hide();
    }
}

function formCategoryChanged(id) {
    // fill in the types
    var $type = $('#' + id + 'Type');
    var alreadySelected = $type.val();
    var options = $type.prop('options');
    $('option', $type).remove();

    var selectedCategory = $('#' + id + 'Category').val();
    var optionsToPush;
    if (selectedCategory === "") { // if no category is selected, insert all attribute types
        optionsToPush = {};
        for (var category in category_type_mapping) {
            for (var index in category_type_mapping[category]) {
                var type = category_type_mapping[category][index];
                optionsToPush[type] = type;
            }
        }
    } else {
        optionsToPush = category_type_mapping[selectedCategory];
    }

    $.each(optionsToPush, function (index, val) {
        var option = new Option(val, val);
        if (val === alreadySelected) {
            option.selected = true;
        }
        options.add(option);
    });
    // enable the form element
    $type.prop('disabled', false);
}

function formTypeChanged(idPrefix) {
    var $type = $('#' + idPrefix + 'Type');
    var currentType = $type.val();

    // Check if current type is correlatable and disable checkbox if yes
    var nonCorrelatingType = non_correlating_types.indexOf(currentType) !== -1;
    $('#' + idPrefix + 'DisableCorrelation').prop('disabled', nonCorrelatingType);
}

function malwareCheckboxSetter(context) {
    var value = $("#" + context + "Category").val();  // get the selected value
    // set the malware checkbox if the category is in the zip types
    $("#" + context + "Malware").prop('checked', formZipTypeValues[value]);
}

function feedFormUpdate() {
    $('.optionalField').hide();
    switch($('#FeedSourceFormat').val()) {
        case 'freetext':
            $('#TargetDiv').show();
            $('#OrgcDiv').show();
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
            $('#OrgcDiv').show();
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
    checkSharingGroup('Feed');
}

function toggleContextFields() {
    $('.context').toggle()
    $('#show_attribute_context').toggleClass("btn-inverse").toggleClass("btn-primary")
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
        url: baseurl + "/attributes/checkOrphanedAttributes/",
    });
}

function checkAttachments() {
    xhr({
        success:function (data, textStatus) {
            var color = 'red';
            var text = ' (Bad links detected)';
            if (data !== undefined && data.trim() == '0') {
                color = 'green';
                text = ' (OK)';
            }
            $("#orphanedFileCount").html('<span class="' + color + '">' + data + text + '</span>');
        },
        type:"get",
        url: "/attributes/checkAttachments/",
    });
}

function loadTagTreemap() {
    xhr({
        success:function (data, textStatus) {
            $(".treemapdiv").html(data);
        },
        type:"get",
        url: "/users/tagStatisticsGraph",
    });
}

function selectAllInbetween(last, current) {
    if (last === false || last === current) {
        return false;
    }
    var from = $(last).parent().parent().index();
    var to = $(current).parent().parent().index();
    if (to < from) {
        var temp = from;
        from = to;
        to = temp;
    }
    $('.select_proposal, .select_attribute, .select').each(function () {
        var index = $(this).parent().parent().index();
        if (index >= from && index <= to) {
            $(this).prop('checked', true);
        }
    });
}

$('#eventToggleButtons button').click(function() {
    var element = $(this).data('toggle-type');
    var $button = $(this).children('span');
    var $element = $('#' + element + '_div');
    if ($button.hasClass('fa-minus')) {
        $button.addClass('fa-plus');
        $button.removeClass('fa-minus');
        $element.hide();
    } else {
        $button.removeClass('fa-plus');
        $button.addClass('fa-minus');
        $element.show();

        // Special cases when another action must be made
        if (element === 'eventtimeline') {
            enable_timeline();
        } else if (element === 'eventgraph') {
            enable_interactive_graph();
        }

        var loadUrl = $(this).data('load-url');
        if (loadUrl) {
            $.get(loadUrl, function(data) {
                $element.html(data);
            }).fail(xhrFailCallback);
        }
    }
});

function quickSubmitGalaxyForm(cluster_ids, additionalData) {
    cluster_ids = cluster_ids === null ? [] : cluster_ids;
    var target_id = additionalData['target_id'];
    var scope = additionalData['target_type'];
    var local = additionalData['local'];
    var mirrorOnEvent = additionalData['mirrorOnEvent'];
    var url = baseurl + "/galaxies/attachMultipleClusters/" + target_id + "/" + scope + "/local:" + local;
    fetchFormDataAjax(url, function(formData) {
        var $formData = $(formData);
        $formData.find("#GalaxyTargetIds").val(JSON.stringify(cluster_ids));
        $formData.find("#GalaxyMirrorOnEvent").prop('checked', mirrorOnEvent);
        if (target_id === 'selected') {
            $formData.find('#GalaxyAttributeIds').val(getSelected());
        }
        $.ajax({
            data: $formData.serialize(),
            beforeSend: function () {
                $(".loading").show();
            },
            success:function (data) {
                if (target_id === 'selected' || scope === 'tag_collection') {
                    location.reload();
                } else {
                    loadGalaxies(target_id, scope);
                    if (mirrorOnEvent) {
                        var event_id = $('#eventgraph_network').data('event-id')
                        loadGalaxies(event_id, 'event');
                    }
                    handleGenericAjaxResponse(data);
                }
            },
            error:function() {
                showMessage('fail', 'Could not add cluster.');
                if (target_id !== 'selected') {
                    loadGalaxies(target_id, scope);
                }
            },
            complete:function() {
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
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
    var $el = $('#hiddenSideMenuData');
    if ($el.length === 0) {
        return;
    }
    var id = $el.data('event-id');
    if (id !== 'undefined' && !skip_reload) {
        $.get(baseurl + "/events/checkPublishedStatus/" + id, function(data) {
            if (data == 1) {
                $('.published').removeClass('hidden');
                $('.not-published').addClass('hidden');
            } else {
                $('.published').addClass('hidden');
                $('.not-published').removeClass('hidden');
            }
        }).fail(xhrFailCallback);
    }
}

$(function() {
    $('#gray_out').click(function() {
        cancelPopoverForm();
        $("#popover_matrix").fadeOut();
        $(".loading").hide();
        resetForms();
        resetEditHoverForms();
    })
});

$(document).keyup(function(e){
    if (e.keyCode === 27) {
        cancelPopoverForm();
        $("#popover_matrix").fadeOut();
        $(".loading").hide();
        resetForms();
        resetEditHoverForms();
    }
});

function closeScreenshot() {
    $("#popover_box").fadeOut();
    $("#screenshot_box").fadeOut(400, function() {
        $(this).remove();
    });
    $("#gray_out").fadeOut();
}

function loadSightingGraph(id, scope) {
    $.get(baseurl + "/sightings/viewSightings/" + id + "/" + scope, function(data) {
        $("#sightingsData").html(data);
    }).fail(xhrFailCallback)
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
        $('.site_admin_enforced').prop('checked', true);
    }
}

function updateMISP() {
    $.get(baseurl + "/servers/update", openConfirmation).fail(xhrFailCallback)
}

function submitMISPUpdate() {
    var formData = $('#PromptForm').serialize();
    xhr({
        data: formData,
        success:function (data) {
            $('#gitResult').text(data).removeClass('hidden');
        },
        complete:function() {
            $(".loading").hide();
            $("#confirmation_box").fadeOut();
            $("#gray_out").fadeOut();
        },
        type:"post",
        url: "/servers/update",
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
        url: baseurl + '/servers/getSubmoduleQuickUpdateForm/' + (submodule_path !== undefined ? btoa(submodule_path) : ''),
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
    var keys = {
        "uuid": "UUID",
        "category": "Category",
        "type": "Type",
        "value": "Value",
        "to_ids": "To IDS",
        "name": "Name",
        "meta-category": "Meta category",
    };

    var uuid = selected;
    var type = additionalData.itemOptions[uuid].type;
    $('#ObjectReferenceReferencedUuid').val(uuid);
    var $targetData = $('#targetData');
    if (type === "Attribute") {
        $targetData.html("");
        for (var k in targetEvent[type][uuid]) {
            if ($.inArray(k, ['uuid', 'category', 'type', 'value', 'to_ids']) !== -1) {
                $targetData.append('<div><span class="bold">' + keys[k] +  '</span>: ' + escapeHtml(targetEvent[type][uuid][k]) + '</div>');
            }
        }
    } else {
        $targetData.html("");
        for (var k in targetEvent[type][uuid]) {
            if (k === 'Attribute') {
                $targetData.append('<br><div><span id="header" class="bold">Attributes:</span>');
                for (var attribute in targetEvent[type][uuid]['Attribute']) {
                    for (var k2 in targetEvent[type][uuid]['Attribute'][attribute]) {
                        if ($.inArray(k2, ['category', 'type', 'value', 'to_ids']) !== -1) {
                            $targetData.append('<div class="indent"><span class="bold">' + keys[k2] + '</span>: ' + escapeHtml(targetEvent[type][uuid]['Attribute'][attribute][k2]) + '</div>');
                        }
                    }
                    $targetData.append('<br>');
                }
            } else {
                if ($.inArray(k, ['name', 'uuid', 'meta-category']) !== -1) {
                    $targetData.append('<div><span class="bold">' + keys[k] +  '</span>: ' + escapeHtml(targetEvent[type][uuid][k]) + '</div>');
                }
            }
        }
    }
}

function delay(callback, ms) {
    var timer = 0;
    return function() {
        var context = this, args = arguments;
        clearTimeout(timer);
        timer = setTimeout(function () {
            callback.apply(context, args);
        }, ms || 0);
    };
}

function previewEventBasedOnUuids(currentValue) {
    if (currentValue === '') {
        $('#event_preview').hide();
    } else {
        $.ajax({
            url: baseurl + "/events/getEventInfoById/" + currentValue,
            type: "get",
            error: function(xhr) {
                $('#event_preview').hide();
                xhrFailCallback(xhr);
            },
            success: function(data) {
                $('#event_preview').html(data).show();
            }
        });
    }
}

function checkNoticeList(type) {
    var fields_to_check = {
        "attribute": ["category", "type"]
    }
    var $noticeMessage = $('#notice_message');
    $noticeMessage.html('<h4>Notices:</h4>');
    $noticeMessage.hide();
    fields_to_check[type].forEach(function(field_name) {
        if (field_name in notice_list_triggers) {
            var field_value = $('#' + type.ucfirst() + field_name.ucfirst()).val();
            if (field_value in notice_list_triggers[field_name]) {
                notice_list_triggers[field_name][field_value].forEach(function(notice) {
                    $noticeMessage.show();
                    $noticeMessage.append(
                        $('<div/>')
                            .append($('<span/>').text('['))
                            .append($('<a/>', {href: baseurl + '/noticelists/view/' + notice['list_id'], class:'bold'}).text(notice['list_name']))
                            .append($('<span/>').text(']: '))
                            .append($('<span/>').text(notice['message']['en']))
                    );
                });
            }
        }
    });

}

$(function() {
    // Show popover for disabled input that contains `data-disabled-reason`.
    $('input:disabled[data-disabled-reason]').popover("destroy").popover({
        placement: 'right',
        html: 'true',
        trigger: 'hover',
        content: function () {
            return $(this).data('disabled-reason');
        }
    });
    $('#PasswordPopover').popover("destroy").popover({
        placement: 'right',
        html: 'true',
        trigger: 'hover',
        content: function () {
            return $(this).data('content');
        }
    });
    $(".queryPopover").click(function() {
        var url = $(this).data('url');
        $.get(url, function(data) {
            var $popover = $('#popover_form');
            $popover.html(data);
            openPopup($popover);
        }).fail(xhrFailCallback)
    });
    $('.servers_default_role_checkbox').click(function() {
        var id = $(this).data("id");
        var state = $(this).is(":checked");
        $(".servers_default_role_checkbox").not(this).attr('checked', false);
        xhr({
            success:function (data) {
                handleGenericAjaxResponse(data);
            },
            type:"get",
            url: '/admin/roles/set_default/' + (state ? id : ""),
        });
    });
    $('.add_object_attribute_row').click(function() {
        var template_id = $(this).data('template-id');
        var object_relation = $(this).data('object-relation');
        var k = $('#last-row').data('last-row');
        var k = k+1;
        $('#last-row').data('last-row', k);
        url = baseurl + "/objects/get_row/" + template_id + "/" + object_relation + "/" + k;
        $.get(url, function(data) {
            $('#row_' + object_relation + '_expand').before($(data).fadeIn()).html();
            var $added_row = $('#row_' + object_relation + '_expand').prev().prev();
            $added_row.find('select.Attribute_value_select option:first').attr('disabled', true);
        }).fail(xhrFailCallback);
    });
    $('.quickToggleCheckbox').toggle(function() {
        var url = $(this).data('checkbox-url');
    });

    $('#setHomePage').parent().click(function(event) {
        event.preventDefault();
        setHomePage();
    });

    $(document.body).on('click', '.privacy-toggle', function() {
        var $this = $(this);
        var $privacy_target = $this.parent().find('.privacy-value');
        if ($this.hasClass('fa-eye')) {
            $privacy_target.text($privacy_target.data('hidden-value'));
            $this.removeClass('fa-eye');
            $this.addClass('fa-eye-slash');

            if ($privacy_target.hasClass('quickSelect')) {
                $privacy_target.click();
            }
        } else {
            $privacy_target.text('****************************************');
            $this.removeClass('fa-eye-slash');
            $this.addClass('fa-eye');
        }
    });

    // For galaxyQuickViewNew.ctp
    $(document.body).on('click', '*[data-clusterid]', function() {
        loadClusterRelations($(this).data('clusterid'));
    });
    $(document.body).popover({
        selector: '.galaxyQuickView ul li b',
        html: true,
        trigger: 'hover',
        container: 'body',
    }).on('shown', function() {
        $('.tooltip').not(":last").remove();
    });
});

// Correlation box for events
$(function() {
    var showAllCorrelations = false;
    var $eventCorrelations = $("#event-correlations");
    var $select = $eventCorrelations.find("select");

    function changeEventOrder() {
        var orderBy = $select.val();
        var array = [];
        $eventCorrelations.find(".event-correlation").each(function () {
            $(this).removeClass("hidden-important");
            array.push({
                "html": $(this).prop("outerHTML"),
                "count": $(this).data("count"),
                "date": $(this).data("date"),
            });
        });
        // sort by defined property
        array.sort(function (a, b) {
            var aProp = a[orderBy];
            var bProp = b[orderBy];
            if (aProp < bProp) {
                return 1;
            }
            if (aProp > bProp) {
                return -1;
            }
            return 0;
        });

        var newHtml = array.map(function (item) {
            return item["html"];
        }).join(" ");

        if ($eventCorrelations.find(".expand-link").length) {
            newHtml += $eventCorrelations.find(".expand-link").prop("outerHTML");
            newHtml += $eventCorrelations.find(".collapse-link").prop("outerHTML");
        }

        $eventCorrelations.find(".correlation-container").html(newHtml);
        changeEventVisibility();
    }

    function changeEventVisibility() {
        if (showAllCorrelations) {
            $eventCorrelations.find(".event-correlation.hidden-important").removeClass("hidden-important");
        } else {
            // Show just first ten
            $eventCorrelations.find(".event-correlation").slice(10).addClass("hidden-important");
        }
    }

    $select.change(function() {
        changeEventOrder();
    });

    $eventCorrelations.on("click", ".expand-link", function() {
        showAllCorrelations = true;
        changeEventVisibility();
        $eventCorrelations.find(".collapse-link").show();
        $(this).hide();
    });

    $eventCorrelations.on("click", ".collapse-link", function() {
        showAllCorrelations = false;
        changeEventVisibility();
        $eventCorrelations.find(".expand-link").show();
        $(this).hide();
    });
});

// Handlers for showing/hiding attribute related events
$(document.body).on("click", ".correlation-expand-button", function() {
    $(this).parent().children(".correlation-expanded-area").show();
    $(this).parent().children(".correlation-collapse-button").show();
    $(this).hide();
}).on("click", ".correlation-collapse-button", function() {
    $(this).parent().children(".correlation-expanded-area").hide();
    $(this).parent().children(".correlation-expand-button").show();
    $(this).hide();
});

// Show full attribute value when value is truncated
$(document.body).on('click', 'span[data-full] a', function(e) {
    e.preventDefault();

    var $parent = $(this).parent();
    var data = $parent.attr('data-full');
    var type = $parent.attr('data-full-type');
    var $box;
    if (type === 'raw' || type === 'cortex') {
        if (type === 'cortex') {
            data = JSON.stringify(JSON.parse(data), null, 2); // make JSON nicer
        }

        $box = $('<pre>').css({
            'background': 'white',
            'border': '0',
            'margin': '0',
        }).text(data);
    } else {
        $box = $('<div>').css({
            'background': 'white',
            'white-space': 'pre-wrap',
            'word-wrap': 'break-word',
            'padding': '1em',
        }).text(data);
    }

    var $popoverFormLarge = $('#popover_form_large');
    $popoverFormLarge.html($box[0].outerHTML);
    openPopup($popoverFormLarge);
})

// Submit quick filter form when user press enter in input field
$(document.body).on('keyup', '#quickFilterField', function(e) {
    if (e.keyCode === 13) { // ENTER key
        $('#quickFilterButton').trigger("click");
    }
});

// Send textarea or select form on CMD+ENTER or CTRL+ENTER
$(document.body).on('keydown', 'textarea, select', function(e) {
    if (e.keyCode === 13 && (e.metaKey || e.ctrlKey)) { // CMD+ENTER or CTRL+ENTER key
        if (e.target.form) {
            $(e.target.form).submit();
        }
    }
});

// Clicking on an element with this class will select all of its contents in a single click
$(document.body).on('click', '.quickSelect', function() {
    var range = document.createRange();
    var selection = window.getSelection();
    range.selectNodeContents(this);
    selection.removeAllRanges();
    selection.addRange(range);
});

// Any link with data-paginator attribute will be treated as AJAX paginator
$(document.body).on('click', 'a[data-paginator]', function (e) {
    e.preventDefault();
    var paginatorTarget = $(this).attr('data-paginator');
    xhr({
        dataType: "html",
        success: function (data) {
            var $target = $(paginatorTarget);
            destroyPopovers($target);
            $target.html(data);
        },
        url: $(this).attr('href'),
    });
});

// Any link with `modal-open` class will be treated as generic modal
$(document.body).on('click', 'a.modal-open', function (e) {
    e.preventDefault();
    openGenericModal($(this).attr('href'));
});

$(document.body).on('click', '[data-popover-popup]', function (e) {
    e.preventDefault();
    var url = $(this).data('popover-popup');
    popoverPopupNew(this, url);
});

$(document).ready(function () {
    var d = new Date()
    if (d.getDate() == 1 && d.getMonth() == 3) {
        $("a:contains('tlp:unclear')").css('background-color', '#ffffff').addClass('special-tag')
    }

    $('#bookmarkThisPageContainer').click(addCurrentPageToBookmark)
});

function destroyPopovers($element) {
    $element.find('[data-dismissid]').each(function() {
        $(this).popover('destroy');
    });
}

function queryEventLock(event_id, timestamp) {
    var interval = null;
    var errorCount = 0;
    var $container = $('#main-view-container');

    function fetchLocks() {
        $.ajax({
            url: baseurl + "/events/checkLocks/" + event_id + "/" + timestamp,
            success: function(data, statusText, xhr) {
                if (xhr.status === 200) {
                    $('#event_lock_warning').remove();
                    $container.append(data);
                } else if (xhr.status === 204) {
                    $('#event_lock_warning').remove();
                }
                errorCount = 0;
            },
            error: function (xhr) {
                if (xhr.status === 401) {
                    var error = '<div id="event_lock_warning" class="alert">' +
                        '<button class="close" data-dismiss="alert">×</button>' +
                        'Unauthorized. Please reload page to log again.' +
                        '</div>';
                    $('#event_lock_warning').remove();
                    $container.append(error);
                }

                ++errorCount;
                if (errorCount > 60) { // 5 mins
                    clearInterval(interval);
                    interval = null;
                }
            }
        });
    }

    document.addEventListener("visibilitychange", function() {
        if (document.visibilityState === 'visible') {
            if (interval === null) {
                interval = setInterval(fetchLocks, 5000); // 5 seconds
            }
        } else {
            if (interval) {
                clearInterval(interval);
                interval = null;
            }
        }
    });

    if (!document.hidden) {
        interval = setInterval(fetchLocks, 5000); // 5 seconds
    }
}

function checkIfLoggedIn() {
    if (!document.hidden) {
        $.get(baseurl + "/users/checkIfLoggedIn.json")
            .fail(function (xhr) {
                if (xhr.status === 403) {
                    window.location.replace(baseurl + "/users/login");
                }
            });
    }
    setTimeout(function () {
        checkIfLoggedIn();
    }, 5000);
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
            $header.children().append($('<th></th>').text(col));
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

function arrayToNestedTable(header, data, table_classes) {
    header = header === undefined ? [] : header;
    table_classes = table_classes === undefined ? ['table', 'table-condensed', 'table-bordered'] : table_classes;
    var $table = $('<table></table>');
    table_classes.forEach(function(classname) {
        $table.addClass(classname);
    });
    if (header.length > 0) {
        var $header = $('<thead><tr></tr></thead>');
        header.forEach(function(col) {
            $header.children().append($('<th></th>').text(col));
        });
        $table.append($header);
    }
    var $body = $('<tbody></tbody>');
    data.forEach(function(row, i) {
        var $tr = $('<tr></tr>');
        row.forEach(function(cell, j) {
            var $td = $('<td></td>').text(cell);
            $tr.append($td);
        });
        $body.append($tr);
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
    xhr({
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
        type:"post",
        url: "/feeds/feedCoverage/" + feedId,
    });
}

function fetchFormDataAjax(url, callback, errorCallback) {
    $.ajax({
        success: function (data) {
            callback(data);
        },
        error:function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Request failed due to an unexpected error.']});
            if (errorCallback !== undefined) {
                errorCallback();
            }
        },
        type: "get",
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

function queryDeprecatedEndpointUsage() {
    $.ajax({
        url: baseurl + '/api/viewDeprecatedFunctionUse',
        type: 'GET',
        success: function(data) {
            $('#deprecationResults').html(data);
        },
        error: function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Could not query the deprecation statistics.']});
        }
    });
}

(function(){
    "use strict";
    $(".datepicker").datepicker({
        format: 'yyyy-mm-dd',
    });
}());

function submitDashboardForm(id) {
    var configData = $('#DashboardConfig').val();
    if (configData != '') {
        try {
            configData = JSON.parse(configData);
        } catch (error) {
            showMessage('fail', error.message)
            return
        }
    } else {
        configData = {};
    }
    configData = JSON.stringify(configData);
    $('#' + id).attr('config', configData);
    $('#genericModal').modal('hide');
    saveDashboardState();
}

function submitDashboardAddWidget() {
    var widget = $('#DashboardWidget').val();
    var config = $('#DashboardConfig').val();
    var width = $('#DashboardWidth').val();
    var height = $('#DashboardHeight').val();
    var el = null;
    var k = $('#last-element-counter').data('element-counter');

    if (config === '') {
        config = '[]'
    }
    try {
        config = JSON.parse(config);
    } catch (error) {
        showMessage('fail', error.message)
        return
    }
    config = JSON.stringify(config);

    $.ajax({
        url: baseurl + '/dashboards/getEmptyWidget/' + widget + '/' + (k+1),
        type: 'GET',
        success: function(data) {
            el = data;
            grid.addWidget(
                el,
                {
                    "width": width,
                    "height": height,
                    "autoposition": 1
                }
            );
            $('#widget_' + (k+1)).attr('config', config);
            $('#last-element-counter').data('element-counter', (k+1));
        },
        complete: function(data) {
            $('#genericModal').modal('hide');
        },
        error: function(data) {
            handleGenericAjaxResponse({'saved':false, 'errors':['Could not fetch empty widget.']});
        }
    });
}

function saveDashboardState() {
    var dashBoardSettings = [];
    $('.grid-stack-item').each(function() {
        if ($(this).attr('config') !== undefined && $(this).attr('widget') !== undefined) {
            var config = $(this).attr('config');
            config = JSON.parse(config);
            var temp = {
                'widget': $(this).attr('widget'),
                'config': config,
                'position': {
                    'x': $(this).attr('data-gs-x'),
                    'y': $(this).attr('data-gs-y'),
                    'width': $(this).attr('data-gs-width'),
                    'height': $(this).attr('data-gs-height')
                }
            };
            dashBoardSettings.push(temp);
        }
    });
    var url = baseurl + '/dashboards/updateSettings'
    fetchFormDataAjax(url, function(formData) {
        var $formContainer = $(formData)
        $formContainer.find('#DashboardValue').val(JSON.stringify(dashBoardSettings))
        var $theForm = $formContainer.find('form')
        xhr({
            data: $theForm.serialize(),
            success:function () {
                showMessage('success', 'Dashboard settings saved.');
            },
            beforeSend:function() {
            },
            type:"post",
            url: $theForm.attr('action')
        });
    })
}

function updateDashboardWidget(element) {
    var $element = $(element);
    if ($element.length) {
        var container_id = $element.attr('id').substring(7);
        var container = $element.find('.widgetContent');
        var titleText = $element.find('.widgetTitleText');
        var temp = JSON.parse($element.attr('config'));
        if (temp['alias'] !== undefined) {
            titleText.text(temp['alias']);
        }
        $.ajax({
            type: 'POST',
            url: baseurl + '/dashboards/renderWidget/' + container_id,
            data: {
                config: $element.attr('config'),
                widget: $element.attr('widget')
            },
            success:function (data) {
                container.html(data);
            }
        });
    }
}

function resetDashboardGrid(grid, save = true) {
    $('.grid-stack-item').each(function() {
        updateDashboardWidget(this);
    });
    if (save) {
        saveDashboardState();
    }
    $('.edit-widget').click(function() {
        var el = $(this).closest('.grid-stack-item');
        var data = {
            id: el.attr('id'),
            config: JSON.parse(el.attr('config')),
            widget: el.attr('widget'),
            alias: el.attr('alias')
        }
        openGenericModalPost(baseurl + '/dashboards/getForm/edit', data);
    });
    $('.remove-widget').click(function() {
        var el = $(this).closest('.grid-stack-item');
        grid.removeWidget(el);
        saveDashboardState();
    });
    $('.widget-export-menu').find('a[data-exporttype]').click(function() {
        var $element = $(this).closest('div[widget]');
        var container_id = $element.attr('id').substring(7);
        var export_type = $(this).data('exporttype')
          $.ajax({
            type: 'POST',
            url: baseurl + '/dashboards/renderWidget/' + container_id + '/export' + export_type + ':1',
            data: {
                config: $element.attr('config'),
                widget: $element.attr('widget')
            },
            success:function (data) {
                if (export_type == 'json') {
                    data = JSON.stringify(data, null, 2);
                }
                var blob = new Blob([data], { type: (export_type == 'json' ? 'application/json' : 'text/csv') });
                var link=window.document.createElement('a');
                link.href=window.URL.createObjectURL(blob);
                link.download=$element.attr('widget') + "_" + container_id + "_export." + export_type;
                link.click();
            }
        });
    })
}

function setHomePage() {
    $.ajax({
        type: 'GET',
        url: baseurl + '/userSettings/setHomePage',
        success: function (data) {
            var $tmp = $(data);
            var currentPage = $('#setHomePage').data('current-page');
            $tmp.find('#UserSettingPath').val(currentPage);
            $.ajax({
                type: 'POST',
                url: baseurl + '/userSettings/setHomePage',
                data: $tmp.serialize(),
                success: function () {
                    showMessage('success', 'Homepage set.');
                    $('#setHomePage').addClass('orange');
                },
            });

        }
    });
}

function addCurrentPageToBookmark() {
    var url = baseurl + '/bookmarks/add'
    fetchFormDataAjax(url, function (formData) {
        var $formData = $(formData);
        var currentPage = $('#bookmarkThisPageContainer').data('current-page');
        var pageTitle = document.title;
        $formData.find('#BookmarkUrl').val(currentPage);
        $formData.find('#BookmarkName').val(pageTitle);
        $.ajax({
            data: $formData.find('form').serialize(),
            beforeSend: function () {
                $(".loading").show();
            },
            success: function (data) {
                showMessage('success', 'Bookmark successfully added');
            },
            error: function () {
                showMessage('fail', 'Could not add current page to list of bookmark');
            },
            complete: function () {
                $(".loading").hide();
            },
            type: "post",
            url: $formData.find('form').attr('action')
        });
    });
}

$(document.body).on('dblclick', '.dblclickElement', function() {
    var href = $(this).closest('tr').find('.dblclickActionElement').attr('href');
    window.location = href;
});

function loadClusterRelations(clusterId) {
    if (clusterId !== undefined) {
        openGenericModal(
            baseurl + '/GalaxyClusters/viewRelationTree/' + clusterId,
            {
                header: "Cluster relation tree",
                classes: "modal-xl",
                bodyStyle: {"min-height": "700px"}
            },
            function() {
                if (window.buildTree !== undefined) {
                    buildTree();
                }
            }
        );
    }
}

function submitGenericFormInPlace(callback, forceApi=false) {
    var $genericForm = $('.genericForm');
    ajaxOptions = {}
    if (forceApi) {
        ajaxOptions['headers'] = { Accept: "application/json" }
    }
    $.ajax(Object.assign({}, {
        type: "POST",
        url: $genericForm.attr('action'),
        data: $genericForm.serialize(), // serializes the form's elements.
        success: function(data) {
            if (typeof data === "object" && data.hasOwnProperty('redirect')) {
                window.location = data.redirect;
                return;
            }
            if (callback) {
                callback(data)
            }

            $('#genericModal').modal('hide').remove();
            $('body').append(data);
            $('#genericModal').modal();
        },
        error: xhrFailCallback,
    }, ajaxOptions));
}

function openIdSelection(clicked, scope, action) {
    var onclick = 'redirectIdSelection(\'' + scope + '\', \'' + action + '\')'
    var html = '<div class="input-append">'
                + '<input class="span2" id="eventIdSelectionInput" type="number" min="1" step="1" placeholder="42">'
                + '<button class="btn btn-primary" type="button" onclick="' + onclick + '">Submit</button>'
            + '</div>';
    openPopover(clicked, html, false, 'right')
}

function redirectIdSelection(scope, action) {
    var id = $('#eventIdSelectionInput').val()
    if (id.length > 0) {
        window.location = baseurl + '/' + scope + '/' + action + '/' + id
    } else {
        showMessage('fail', 'Not an valid event id');
    }
}

$(document.body).on('click', '.populateActionTrigger', function() {
    var populate_script = $(this).data('request-script');
    populate_script = atob(populate_script);
    populate_script = populate_script.replace(/\{\{[A-Za-z0-9#_]*\}\}/gi, function(fieldName) {
        fieldName = fieldName.substring(2, fieldName.length -2);
        if ($(fieldName).is('input')) {
            return $(fieldName).val();
        } else {
            //fieldName = fieldName.substring(1, fieldName.length);
            var toReturn = $(fieldName + " option:selected").val();
            return toReturn;
        }
    });
    populate_script = JSON.parse(populate_script);
    var update_target = $(this).data('update-target');
    $.ajax({
        data: JSON.stringify(populate_script['body']),
        headers: {
            "Accept": "application/json",
            "Content-type": "application/json"
        },
        success: function (data) {
            if (typeof(data) != 'object') {
                $('#' + update_target).val(data);
            } else {
                $('#' + update_target).empty();
                $('#' + update_target).append($('<option selected disabled hidden>').text('Choose'));
                $.each(data, function(key, value) {
                    $('#' + update_target).append($('<option>').val(key).text(value));
                });
            }
        },
        error: function(data) {
            showMessage('fail', data['responseJSON']['errors']);
        },
        type: populate_script['type'],
        url: baseurl + populate_script['uri']
    })
});

$(document.body).on('click', '.hex-value-convert', function() {
    var $hexValueSpan = $(this).parent().children(':first-child');
    var val = $hexValueSpan.text().trim();
    if (!$hexValueSpan.hasClass('binary-representation')) {
        var bin = [];
        val.split('').forEach(function (entry) {
            var temp = parseInt(entry, 16).toString(2);
            bin.push(Array(5 - (temp.length)).join('0') + temp);
        });
        bin = bin.join(' ');
        $hexValueSpan
            .text(bin)
            .attr('data-original-title', 'Binary representation')
            .addClass('binary-representation');
        if ($hexValueSpan.attr('title')) {
            $hexValueSpan.attr('title', 'Binary representation');
        }
        $(this)
            .attr('data-original-title', 'Switch to hexadecimal representation')
            .attr('aria-label', 'Switch to hexadecimal representation');
    } else {
        var hex = '';
        val.split(' ').forEach(function (entry) {
            hex += parseInt(entry, 2).toString(16).toUpperCase();
        });
        $hexValueSpan
            .text(hex)
            .attr('data-original-title', 'Hexadecimal representation')
            .removeClass('binary-representation');
        if ($hexValueSpan.attr('title')) {
            $hexValueSpan.attr('title', 'Hexadecimal representation');
        }
        $(this)
            .attr('data-original-title', 'Switch to binary representation')
            .attr('aria-label', 'Switch to binary representation');
    }
});

// Tag popover with taxonomy description
(function() {
    var tagDataCache = {};
    function fetchTagInfo(tagId, callback) {
        if (tagId in tagDataCache) {
            callback(tagDataCache[tagId]);
            return;
        }

        $.ajax({
            success: function (data) {
                var tagData;
                for (var i = 0; i < data.length; i++) {
                    var tag = data[i];
                    if (tag.Tag.id == tagId) {
                        tagData = data[i]
                        break;
                    }
                }
                if (tagData !== undefined) {
                    callback(tagData);
                    tagDataCache[tagId] = tagData;
                }
            },
            type: "get",
            url: baseurl + "/tags/search/" + tagId + "/1/1"
        })
    }

    function constructTaxonomyInfo(tagData) {
        var predicateText = tagData.TaxonomyPredicate.expanded;
        if (tagData.TaxonomyPredicate.TaxonomyEntry) {
            predicateText += ": " + tagData.TaxonomyPredicate.TaxonomyEntry[0].expanded;
        }

        var $predicate = $('<div/>').append(
            $('<h3/>').css("margin-top", "5px").text('Tag info'),
            $('<p/>').css("margin-bottom", "5px").text(predicateText)
        );
        if (tagData.TaxonomyPredicate.description) {
            $predicate.append($('<p/>').css("margin-bottom", "5px").append(
                $('<strong/>').text('Description: '),
                $('<span/>').text(tagData.TaxonomyPredicate.description)
            ));
        }
        if (tagData.TaxonomyPredicate.TaxonomyEntry && tagData.TaxonomyPredicate.TaxonomyEntry[0].numerical_value) {
            $predicate.append($('<p/>').css("margin-bottom", "5px").append(
                $('<strong/>').text('Numerical value: '),
                $('<span/>').text(tagData.TaxonomyPredicate.TaxonomyEntry[0].numerical_value)
            ));
        }
        var $meta = $('<div/>').append(
            $('<h3/>').text('Taxonomy: ' + tagData.Taxonomy.namespace.toUpperCase()),
            $('<p/>').css("margin-bottom", "5px").append(
                $('<span/>').text(tagData.Taxonomy.description)
            )
        )
        return $('<div/>').append($predicate, $meta)
    }

    var popoverDebounce = null;
    $(document.body).on({
        mouseover: function() {
            var $tag = $(this);
            popoverDebounce = setTimeout(function() {
                popoverDebounce = null;
                var tagId = $tag.data('tag-id');

                fetchTagInfo(tagId, function (tagData) {
                    if (tagData.TaxonomyPredicate === undefined) {
                        return;
                    }
                    // Check if user cursor is still on tag
                    if ($(':hover').last()[0] !== $tag[0]) {
                        return;
                    }
                    $tag.popover({
                        html: true,
                        container: 'body',
                        placement: 'top',
                        template: '<div class="popover"><div class="arrow"></div><div class="popover-content"></div></div>',
                        content: function () {
                            return constructTaxonomyInfo(tagData);
                        }
                    }).popover('show');
                });
            }, 200);
        },
        mouseout: function() {
            if (popoverDebounce) {
                clearTimeout(popoverDebounce);
                popoverDebounce = null;
            }
            $(this).popover('destroy');
        }
    }, 'a.tag[data-tag-id]');
})();

// Highlight column for roles table
$('td.rotate').hover(function() {
    var $table = $(this).closest('table');
    var t = parseInt($(this).index()) + 1;
    $table.find('td:nth-child(' + t + ')').css('background-color', '#CFEFFF');
}, function() {
    var $table = $(this).closest('table');
    var t = parseInt($(this).index()) + 1;
    $table.find('td:nth-child(' + t + ')').css('background-color', '');
});

function enableWorkflowDebugMode(workflow_id, currentEnabledState, callback) {
    var enabled = currentEnabledState ? false : true
    var url = baseurl + '/workflows/debugToggleField/' + workflow_id + '/' + (enabled ? '1' : '0')
    fetchFormDataAjax(url, function (formData) {
        var $formData = $(formData);
        $.ajax({
            data: $formData.find('form').serialize(),
            beforeSend: function () {
                $(".loading").show();
            },
            success: function (data) {
                showMessage('success', data.message);
                if (callback) {
                    callback(data)
                }
            },
            error: function () {
                showMessage('fail', 'Could not toggle debug mode.');
            },
            complete: function () {
                $("#popover_form").fadeOut();
                $("#gray_out").fadeOut();
                $(".loading").hide();
            },
            type: "post",
            url: $formData.find('form').attr('action')
        });
    });
}

// Used in audit and access logs
function filterSearch(callback) {
    $('td[data-search]').mouseenter(function() {
        var $td = $(this);
        var searchValue = $td.data('search-value');
        if (searchValue.length === 0) {
            return;
        }

        $td.find('#quickEditButton').remove(); // clean all similar if exist
        var $div = $('<div id="quickEditButton"></div>');
        $div.addClass('quick-edit-row-div');
        var $span = $('<span></span>');
        $span.addClass('fa-as-icon fa fa-search-plus');
        $span.css('font-size', '12px');
        $span.prop('title', 'Filter by this value');
        $div.append($span);
        $td.append($div);

        $span.click(function (e) {
            var searchKey = $td.data('search');
            callback(e, searchKey, searchValue);
        });

        $td.off('mouseleave').on('mouseleave', function() {
            $div.remove();
        });
    });
}