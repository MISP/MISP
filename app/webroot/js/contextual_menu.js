class ContextualMenu {
    constructor(options) {
        this.options = options;
        this.trigger_container = options.trigger_container;
        this.container = options.container;
        this.bootstrap_popover = options.bootstrap_popover;
        this.right_click = options.right_click;
        this.has_been_shown_once = false;
        this.items = {};
        this.__is_shown = false;
        this.__globalCounter = 0;

    if (this.bootstrap_popover) {
            if (typeof $.fn.popover != 'function') { // boostrap loaded
                console.log("Boostrap not loaded or does not support popover");
                this.menu = this.__create_menu_div();
            } else {
                this.menu = this.__create_menu_div_bootstrap_popover();
            }
        } else {
            this.menu = this.__create_menu_div();
        }

    }

    /* Addition */
    add_button(options) {
        this.__create_divider_if_needed('btn');
        var btn = this.__create_button(options);
        this.items[btn.id] = btn;
    }

    add_checkbox(options) {
        this.__create_divider_if_needed('checkbox');
        var checkbox = this.__create_checkbox(options);
        this.items[checkbox.id] = checkbox;
    }

    add_input(options) {
        this.__create_divider_if_needed('input');
        var input = this.__create_input(options);
        this.items[input.id] = input;
    }

    add_slider(options) {
        this.__create_divider_if_needed('slider');
        var slider = this.__create_slider(options);
        this.items[slider.id] = slider;
    }

    add_select(options) {
        this.__create_divider_if_needed('select');
        var select = this.__create_select(options);
        this.items[select.id] = select;
    }

    add_select_button(options) {
        this.__create_divider_if_needed('select_button');
        var select_button = this.__create_select_button(options);
        this.items[select_button.id] = select_button;
    }

    add_fileinput(options) {
        this.__create_divider_if_needed('fileinput');
        var fileinput = this.__create_fileinput(options);
        this.items[fileinput.id] = fileinput;
    }

    add_action_table(options) {
        this.__create_divider_if_needed('action_table');
        var action_table = this.__create_action_table(options);
        this.items[action_table.id] = action_table;
    }

    create_divider(height) {
        var divider = document.createElement('li');
        divider.classList.add("contextual-menu-divider");
        if (height !== undefined) {
            divider.style.height = height+"px";
            divider.style.marginTop = "15px";
            divider.style.marginBottom = "15px";
        }
        this.menu.appendChild(divider);
        this.previous_context = undefined; // do not draw another line
    }

    /* Manipulation */
    add_options(id, values) {
        var select = this.items[id];
        var selected_value = select.value;
        select.innerHTML = ""; // ensure uniqueness
        this.__add_options_to_select(select, values);
        select.value = selected_value;
    }


    /* Private */
    __get_uniq_index() {
        this.__globalCounter++;
        return this.__globalCounter-1;
    }

    __toggleMenu(x, y, hide) {
        var that = this;
        if(this.__is_shown || hide) {
            this.menu.style.visibility = 'hidden';
        } else {
            this.menu.style.left = x+'px';
            this.menu.style.top = y+'px';
            this.menu.style.visibility = 'visible';
        }
        this.__is_shown = !this.__is_shown;
    }

    __create_menu_div() {
        var div = document.createElement('div');
        div.classList.add("contextual-menu");
        div.classList.add("contextual-menu-styling");
        this.container.appendChild(div);
        // register on click for the trigger_container
        var that = this;
        if (this.right_click) {
            this.trigger_container.addEventListener('contextmenu', function(evt) {
                evt.preventDefault();
                var offsetX = $(that.trigger_container).offset().left;
                var offsetY = $(that.trigger_container).offset().top-40;
                that.__toggleMenu(evt.pageX-offsetX, evt.pageY-offsetY);
            });
            // hide the contextual menu on any click
            document.getElementsByTagName("BODY")[0].addEventListener("click", function(evt) {
                that.__toggleMenu(evt.pageX, evt.pageY, true);
            });
        } else {
            this.trigger_container.addEventListener("click", function(evt) {
                var offsetX = 0;
                var offsetY = 1;
                that.__toggleMenu(evt.pageX+offsetX, evt.pageY+offsetY);
            });
        }
        return div;
    }

    __create_menu_div_bootstrap_popover() {
        var div = document.createElement('div');
        div.classList.add("contextual-menu");
        this.container.appendChild(div);
        var that = this;
        this.trigger_container.tabIndex = 0; // required for the popover focus feature
	var additional_styling = this.options.style === undefined ? "" : this.options.style;
        $(this.trigger_container).popover({
            container: 'body',
            html: true,
            placement: "bottom",
            content: function () {return $(that.menu); }, // return contextual menu html
            trigger: "manual",
            template: '<div class="popover" id="popover-contextual-menu-'+this.trigger_container.id+'" role="tooltip" style="'+additional_styling+'"><div class="arrow"></div></h3><div class="popover-content"></div></div>'
        })

        // Overwrite the default popover behavior: hidding cause the popover to be detached from the DOM, making impossible to fetch input values in the form
        $(this.trigger_container).click (function(e) {
            if (that.has_been_shown_once) {
                $('#popover-contextual-menu-'+this.id).toggle();
            } else {
                that.has_been_shown_once = true;
                $(this).popover('show');
            }
        });
        return div;
    }

    __create_divider_if_needed(context) {
        if (this.previous_context === undefined) {
            this.previous_context = context;
        } else if (this.previous_context != context) {
            this.create_divider();
            this.previous_context = context;
        }
        return;
    }

    __create_button(options) {
        var btn = document.createElement('button');
        btn.classList.add("btn-dropdown", "btn", "btn-"+options.type);
        btn.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id;
        if(options.tooltip !== undefined) {
            btn.title = options.tooltip;
        }
        var span = document.createElement('span');
        span.classList.add("fa", "fa-"+options.icon);
        btn.innerHTML = span.outerHTML + options.label;
        if(options.event !== undefined) {
            btn.addEventListener("click", function(evt) {
                options.event();
            });
        }
        this.menu.appendChild(btn);
        return btn;
    }

    __create_input(options) {
        var input = document.createElement("input");
        input.classList.add("form-group");
        input.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id;
        if(options.tooltip !== undefined) {
            input.title = options.tooltip;
        }
        if(options.placeholder !== undefined) {
            input.placeholder = options.placeholder;
        }

        if(options.event !== undefined) {
            input.addEventListener("change", function(evt) {
                options.event(evt.target.value);
            });
        }
        this.menu.appendChild(input);

        if (options.typeahead !== undefined) {
            var typeaheadOption = options.typeahead;
            $('#'+input.id).typeahead(typeaheadOption);
        }
        return input;
    }

    __create_fileinput(options) {
        var div = document.createElement('div');
        var label = document.createElement('label');
        label.innerHTML = options.label+":";
        var input = document.createElement("input");
        input.classList.add("form-group");
        input.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id;
        if(options.tooltip !== undefined) {
            input.title = options.tooltip;
        }
        input.type = "file";
        input.accept = ".json";
        var file_status = document.createElement('span');
        file_status.id = input.id + "_status";
        input.dataset.relatedStatusId = file_status.id;
        if(options.event !== undefined) {
            input.addEventListener("change", function(evtInput) {
                var file = this.files[0];
                if (file) {
                    var reader = new FileReader();
                    reader.readAsText(file, "UTF-8");
                    reader.onload = function (evtReader) {
                        document.getElementById(evtInput.target.dataset.relatedStatusId).innerHTML = "File loaded";
                        var content = evtReader.target.result;
			evtInput.target.value = '';
                        options.event(content);
                    };
                    reader.onerror = function (evtReader) {
                        document.getElementById(evtInput.target.dataset.relatedStatusId).innerHTML = "Error while reading the file";
                    };
                    reader.onprogress = function (evtReader) {
                        if (evtReader.lengthComputable) {
                            var loaded = (evtReader.loaded / evtReader.total)*100;
                            if (loaded < 100) {
                                document.getElementById(evtInput.target.dataset.relatedStatusId).innerHTML = "Reading file: "+loaded.toFixed(2)+"%";
                            }
                        }
                    };
                }
            });
        }
        div.appendChild(label);
        div.appendChild(input);
        div.appendChild(file_status);
        this.menu.appendChild(div);
        return input;
    }

    __create_slider(options) {
        var div = document.createElement('div');
        var label = document.createElement('label');
        label.innerHTML = options.label+":";
        if(options.tooltip !== undefined) {
            label.title = options.tooltip;
        }
        var slider = document.createElement('input');
        slider.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id;
        slider.type = "range";
        slider.min = options.min;
        slider.max = options.max;
        slider.value = options.value;
        slider.step = options.step;
        var slider_val = options.value == undefined ? 0 : options.value;
        slider.value = slider_val;
        var span = document.createElement('span');
        span.innerHTML = slider_val;
        span.id = slider.id + "_span";
        if(options.event !== undefined) {
            slider.addEventListener('input', function(evt) {
                span.innerHTML = evt.target.value; // Update associated span
                options.event(evt.target.value);
            });
        }
        $(slider).on('reflectOnSpan', function(evt) {
            span.innerHTML = evt.target.value; // Update associated span
        });
        div.appendChild(label);
        div.appendChild(span);
        if (options.applyButton !== undefined) {
            var button = document.createElement('button');
            button.innerHTML = "Apply";
            button.classList.add("btn");
            button.addEventListener("click", function(evt) { options.eventApply(slider.value); });
            div.appendChild(button);
        }
       div.appendChild(slider);
       this.menu.appendChild(div);
       return slider;
    }

    __create_checkbox(options) {
        var checkbox = document.createElement('input');
        var label = document.createElement('label');
        checkbox.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id;
        checkbox.type = "checkbox";
        checkbox.checked = options.checked;
        if(options.tooltip !== undefined) {
            label.title = options.tooltip;
        }
        label.appendChild(checkbox);
        label.appendChild(document.createTextNode(options.label));
        if(options.event !== undefined) {
            label.addEventListener("change", function(evt) { options.event(evt.target.checked); });
        }
        this.menu.appendChild(label);
        return checkbox;
    }

    __create_select(select_options) {
        var select = document.createElement('select');
        var label = document.createElement('label');
        label.innerHTML = select_options.label+":";
        label.title = select_options.tooltip;
        select.id = select_options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : select_options.id;
        this.__add_options_to_select(select, select_options.options);
        if(select_options.default !== undefined) {
            select.value = select_options.default;
        }
        this.menu.appendChild(label);
        this.menu.appendChild(select);
        if(select_options.event !== undefined) {
            select.addEventListener("change", function(evt) { select_options.event(evt.target.value); });
        }
        return select;
    }

    __create_select_button(options) {
        var div = document.createElement('div');
	div.style = "width: inherit;";
        var select = document.createElement('select');
        var label = document.createElement('label');
        var button = document.createElement('button');
        button.classList.add("btn-dropdown", "btn", "btn-default");
        button.style = "padding: 4px 12px; line-height: 20px; margin-left: 7px;";
        button.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id+"_btn";
	button.innerHTML = options.textButton !== undefined ? options.textButton : "";
        label.innerHTML = options.label+":";
        label.title = options.tooltip;
        select.id = options.id === undefined ? 'contextualMenu_'+this.__get_uniq_index() : options.id+"_select";
        button.dataset.correspondingId = select.id;
        this.__add_options_to_select(select, options.options);
        if(options.default !== undefined) {
            select.value = options.default;
        }
        div.appendChild(select);
        div.appendChild(button);
        this.menu.appendChild(label);
        this.menu.appendChild(div);
        if(options.event !== undefined) {
            button.addEventListener("click", function(evt) { 
		var corresponding_select_id = evt.target.dataset.correspondingId;
		var selected_value = $('#'+corresponding_select_id).val();
		options.event(selected_value);
	    });
        }
        return button;
    }

    __add_options_to_select(select, options) {
        for(var value of options) {
            var option = document.createElement('option');
            if (typeof value === 'object') {
                option.value = value.value;
                option.innerHTML = value.text;
            } else {
                option.value = value;
                option.innerHTML = value;
            }
            select.appendChild(option);
        }
    }

    __create_action_table(options) {
        var action_table = new ActionTable(options);
        return action_table;
    }
}
