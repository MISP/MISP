class ActionTable {
	constructor(options) {
		this.__globalCounter = 0;
		this.options = options;
		this.id = options.id;
		this.container = options.container;
		this.classes = options.classes;
		this.table_title = options.title;
		this.header = options.header;
		this.onAddition = options.onAddition;
		this.onRemove = options.onRemove;
		this.header.push("Action");
		this.row_num = this.header.length;
		this.data = options.data === undefined ? [] : options.data;
		this.tr_id_mapping = {};
		this.control_items = options.control_items;
		this.header_action_button = options.header_action_button === undefined ? {} : options.header_action_button;
		if (options.header_action_button !== undefined) {
			this.header_action_button_style = this.header_action_button.style === undefined ? {} : this.header_action_button.style;
			this.additionEnabled = this.header_action_button.additionEnabled === undefined ? true : this.header_action_button.additionEnabled;
			this.additionButtonDisabled = this.header_action_button.disabled === undefined ? false : this.header_action_button.disabled;
		} else {
			this.header_action_button_style = {};
			this.additionEnabled = true;
			this.additionButtonDisabled = false;
		}

		this.row_action_button = options.row_action_button === undefined ? {} : options.row_action_button;
		if (options.row_action_button !== undefined) {
			this.row_action_button_style = this.row_action_button.style === undefined ? {} : this.row_action_button.style;
			this.removalEnabled = this.row_action_button.removalEnabled === undefined ? true : this.row_action_button.removalEnabled;
		} else {
			this.row_action_button_style = {};
			this.removalEnabled = true;
		}

		this.selects = {};

		this.__create_table();
	}

	__get_uniq_index() {
		this.__globalCounter++;
		return this.__globalCounter-1;
	}

	add_row(row) {
		if (!this.__data_already_exists(row)) {
			var id = this.__add_row(row);
			this.tr_id_mapping[this.data.length] = id;
			this.data.push(row);
		}
	}

	delete_row(row_id) {
		var tr = document.getElementById(row_id);
		var array = this.__get_array_from_DOM_row(tr);
		var data_index = this.__find_array_index(array, this.data);
		tr.outerHTML = "";
		this.data.splice(data_index, 1);
	}

	delete_row_index(row_pos) {
		var tr = this.get_DOM_row(row_pos);
		var array = this.__get_array_from_DOM_row(tr);
		var data_index = this.__find_array_index(array, this.data);
		tr.outerHTML = "";
		this.data.splice(data_index, 1);
	}

	get_DOM_row(row_pos) {
		var row_id = this.tr_id_mapping[row_pos];
		var tr = document.getElementById(row_id);
		return tr;
	}

	get_data() {
		return this.data;
	}

	clear_table() {
		var dataLength = this.data.length;
		for (var i=0; i<dataLength; i++) {
			this.delete_row_index(i);
		}
	}

	set_table_data(data) {
		this.clear_table();
		for (var i in data) {
			this.add_row(data[i]);
		}
	}

	add_options(id, values) {
		var select = this.selects[id];
		var selected_value = select.value;
		select.innerHTML = ""; // ensure uniqueness
		this.__add_options_to_select(select, values);
		select.value = selected_value;
	}

	__get_array_from_DOM_row(tr) {
		var children = tr.children;
		var array = [];
		for (var i = 0; i < children.length-1; i++) {
			array.push(children[i].innerText);
		}
		return array;
	}

	__data_already_exists(data) {
		return this.__find_array_index(data, this.data) >= 0;
	}

	__find_array_index(value, array) {
		for (var i in array) {
			if (JSON.stringify(array[i]) === JSON.stringify(value)) { // compare array
				return i;
			}
		}
		return -1;
	}

	__create_table() {
		if (this.table_title !== undefined) {
			var label = document.createElement('label');
			label.innerHTML = this.table_title;
			this.container.appendChild(label);
		}
		this.form = document.createElement('form');
		this.table = document.createElement('table');
		this.table.classList.add("table", "table-bordered", "action-table");
		if (this.classes !== undefined) {
			for (var i in this.classes) {
				this.table.classList.add(this.classes[i]);
			}
		}
		this.thead = document.createElement('thead');
		this.tbody = document.createElement('tbody');
		var trHead = document.createElement('tr');
		for (var col of this.header) {
			var th = document.createElement('th');
			th.innerHTML = col;
			trHead.appendChild(th);
		}
		this.thead.appendChild(trHead);

		this.__add_control_row();

		for (var row of this.data) {
			this.__add_row(row);
		}
		this.table.appendChild(this.thead);
		this.table.appendChild(this.tbody);
		this.form.appendChild(this.table);
		this.container.appendChild(this.form);
	}

	__add_row(row) {
		var tr = document.createElement('tr');
		tr.id = "tr_" + this.__uuidv4();
		for (var col of row) {
			var td = document.createElement('td');
			td.innerHTML = col;
			tr.appendChild(td);
		}
		this.__add_action_button(tr);
		this.tbody.appendChild(tr);
		return tr.id;
	}

	__add_control_row() {
		var tr = document.createElement('tr');
		for (var itemOption of this.control_items) {
			var td = document.createElement('td');
			var item = this.__add_control_item(itemOption);
			if (itemOption.colspan !== undefined) {
				td.colSpan = itemOption.colspan;
			}
			td.appendChild(item);
			tr.appendChild(td);
		}
		var td = document.createElement('td');

		var btn = document.createElement('button');
		var header_action_button_style = this.header_action_button.style === undefined ? {} : this.header_action_button.style;
		if (header_action_button_style.type !== undefined) {
			btn.classList.add("btn", "btn-"+header_action_button_style.type);
		} else {
			btn.classList.add("btn", "btn-primary");
		}
		if (header_action_button_style.tooltip !== undefined) {
			btn.title = header_action_button_style.tooltip;
		}
		if (header_action_button_style.icon !== undefined) {
			btn.innerHTML = '<span class="fa '+header_action_button_style.icon+'"></span>';
		} else {
			btn.innerHTML = '<span class="fa fa-plus-square"></span>';
		}
		btn.type = "button";
		btn.disabled = this.additionButtonDisabled;

		var that = this;
		btn.addEventListener("click", function(evt) {
			var data = [];
			for (var elem of that.form.elements) {
				if (elem.classList.contains('form-group')) {
					data.push(elem.value);
				}
			}
			if (that.additionEnabled) {
				that.add_row(data);
			}
			if (that.onAddition !== undefined) {
				that.onAddition(data, that);
			}
		});

		td.appendChild(btn);

		tr.appendChild(td);
		this.thead.appendChild(tr);
	}

	__add_control_item(options) {
		var item;
		switch(options.DOMType) {
			case "select":
				item = this.__create_select(options.item_options);
				this.selects[item.id] = item;
				break;
			case "input":
				item = this.__create_input(options.item_options);
				break;
			case "empty":
				item = this.__create_empty(options.item_options);
				break;
			default:
				break;
		}
		return item;
	}

	__add_action_button(tr) {
		var that = this;
		var td = document.createElement('td');
		var btn = document.createElement('button');
		btn.classList.add("btn", "btn-danger");
		btn.innerHTML = '<span class="fa fa-trash-o"></span>';
		btn.type = "button";
		btn.setAttribute('rowID', tr.id);
		if (that.row_action_button_style.tooltip !== undefined) {
			btn.title = that.row_action_button_style.tooltip;
		}
		if (that.row_action_button_style.style !== undefined) {
			btn.style = that.row_action_button_style.style;
		}
		var that = this;
		btn.addEventListener("click", function(evt) {
			if (that.onRemove !== undefined) {
				var tr = document.getElementById(this.getAttribute('rowID'));
				var data = that.__get_array_from_DOM_row(tr);
				that.onRemove(data, that);
			}
			if (that.removalEnabled) {
				that.delete_row(this.getAttribute('rowID'));
			}
		});
		td.appendChild(btn);

		if (that.row_action_button.others !== undefined) {
			for (var i in that.row_action_button.others) {
				var newBtnOptions = that.row_action_button.others[i];

				var btn_style = newBtnOptions.style !== undefined ? newBtnOptions.style : {};
				var btn = document.createElement('button');
				btn.type = "button";
				if (btn_style.type !== undefined) {
					btn.classList.add("btn", "btn-"+btn_style.type);
				} else {
					btn.classList.add("btn", "btn-primary");
				}
				if (btn_style.icon !== undefined) {
					btn.innerHTML = '<span class="fa '+btn_style.icon+'"></span>';
				} else {
					btn.innerHTML = '<span class="fa fa-check"></span>';
				}
				if (btn_style.title !== undefined) {
					btn.title = btn_style.title;
				}
				if (btn_style.style !== undefined) {
					btn.style = btn_style.style+"margin-left: 3px";
				} else {
					btn.style = "margin-left: 3px";
				}
				btn.setAttribute('rowID', tr.id);
				if (newBtnOptions.event !== undefined) {
					btn.addEventListener("click", function(evt) {
						var tr = document.getElementById(this.getAttribute('rowID'));
						var data = that.__get_array_from_DOM_row(tr);
						newBtnOptions.event(data, that);
					});
				}
				td.appendChild(btn);
			}
		}

		tr.appendChild(td);
	}

	__create_empty(options) {
		var empty = document.createElement('span');
		empty.classList.add("form-group");
		empty.id = options.id !== undefined ? options.id : 'actionTable_controlSelect_'+this.__get_uniq_index();
		return empty;
	}

	__create_input(options) {
		var input = document.createElement('input');
		input.classList.add("form-group");
		input.id = options.id !== undefined ? options.id : 'actionTable_controlSelect_'+this.__get_uniq_index();
		if (options.style !== undefined) {
			input.style = options.style;
		}
		if (options.placeholder !== undefined) {
			input.placeholder = options.placeholder;
		}
		if (options.disabled !== undefined) {
			input.disabled = options.disabled;
		}
		if (options.typeahead !== undefined) {
			var typeaheadOption = options.typeahead;
			$('#'+input.id).typeahead(typeaheadOption);
		}
		return input;
	}

	__create_select(select_options) {
		var select = document.createElement('select');
		select.classList.add("form-group");
		select.id = select_options.id !== undefined ? select_options.id : 'actionTable_controlSelect_'+this.__get_uniq_index();
		select.style.width = "100%";
		this.__add_options_to_select(select, select_options.options);
		if(select_options.default !== undefined) {
			select.value = select_options.default;
		}
		return select;
	}

	__add_options_to_select(select, options) {
		for(var value of options) {
			var option = document.createElement('option');
			if (Array.isArray(value)) { // array of type [value, text]
				option.value = value[1];
				option.innerHTML = value[1];
			} else { // only value, text=value
				option.value = value;
				option.innerHTML = value;
			}
			select.appendChild(option);
		}
	}

	__uuidv4() {
		return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
			var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
			return v.toString(16);
		});
	}
}
