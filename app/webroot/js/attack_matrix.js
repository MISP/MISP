//function enable_attack_matrix() {
//	var container = document.getElementById("matrix_container");
//	fetch_matrix();
//}
//
//function fetch_matrix() {
//	container.html(data);
//}

$(document).ready(function() {
	$('.matrix-interaction').click(function(event) {
		console.log($(this).attr('data-tag_name'));
	});
});
