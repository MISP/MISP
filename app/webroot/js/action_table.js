class ActionTable {
	constructor(options) {
		this.__globalCounter = 0;
		this.options = options;
		this.id = options.id;
		this.container = options.container;
		this.table_title = options.title;
		this.header = options.header;
		this.onAddition = options.onAddition;
		this.header.push("Action");
		this.row_num = this.header.length;
		this.data = options.data == undefined ? [] : options.data;
		this.control_items = options.control_items;

		this.selects = {};

		this.__create_table();
	}

	__get_uniq_index() {
		this.__globalCounter++;
		return this.__globalCounter-1;
	}

	add_row(row) {
		if (!this.__data_already_exists(row)) {
			this.data.push(row);
			this.__add_row(row);
		}
	}

	delete_row(row_id) {
		var tr = document.getElementById(row_id);
		var array = this.__get_array_from_DOM_row(tr);
		var data_index = this.__find_array_index(array, this.data);
		tr.outerHTML = "";
		this.data.splice(data_index, 1);
	}

	get_data() {
		return this.data;
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
		tr.id = "tr_" + this.__get_uniq_index();
		for (var col of row) {
			var td = document.createElement('td');
			td.innerHTML = col;
			tr.appendChild(td);
		}
		this.__add_action_button(tr);
		this.tbody.appendChild(tr);
	}

	__add_control_row() {
		var tr = document.createElement('tr');
		for (var item of this.control_items) {
			var td = document.createElement('td');
			var item = this.__add_control_item(item);
			td.appendChild(item);
			tr.appendChild(td);
		}
		var td = document.createElement('td');
		var btn = document.createElement('button');
		btn.classList.add("btn", "btn-primary");
		btn.innerHTML = '<span class="fa fa-plus-square"></span>';
		btn.type = "button";

		var that = this;
		btn.addEventListener("click", function(evt) {
			var data = [];
			for (var elem of that.form.elements) {
				if (elem.classList.contains('form-group')) {
					data.push(elem.value);
				}
			}
			that.add_row(data);
			if (that.onAddition !== undefined) {
				that.onAddition(data);
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
			default:
				break;
		}
		return item;
	}

	__add_action_button(tr) {
		var td = document.createElement('td');
		var btn = document.createElement('button');
		btn.classList.add("btn", "btn-danger");
		btn.innerHTML = '<span class="fa fa-trash-o"></span>';
		btn.type = "button";
		btn.setAttribute('rowID', tr.id);
		var that = this;
		btn.addEventListener("click", function(evt) {
			that.delete_row(this.getAttribute('rowID'));
		});
		td.appendChild(btn);
		tr.appendChild(td);
	}

	__create_input(options) {
		var input = document.createElement('input');
		input.classList.add("form-group");
		input.id = options.id !== undefined ? options.id : 'actionTable_controlSelect_'+this.__get_uniq_index();
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
			option.value = value;
			option.innerHTML = value;
			select.appendChild(option);
		}
	}
}
