/**
 * support for touch devices without the need
 */

$(document).ready(function() {
	var touchStartTime = 0;
	var touchTarget = null;

	document.body.addEventListener('touchstart', function(ev) {
		if (touchStartTime == 0) {
			touchStartTime = (new Date()).getTime();
			touchTarget = ev.target;	
		}
	}, false);
	document.body.addEventListener('touchcancel', function(ev) {
		// iphone only
		touchStartTime = 0;
		touchTarget = null;
	}, false);
	document.body.addEventListener('touchend', function(ev) {
		var touchEndTime = (new Date()).getTime();
		var canTrigger = (touchStartTime > 0 && (touchEndTime - touchStartTime) > 500 && touchTarget == ev.target);

		// reset the variables BEFORE calling the event handler
		// so that our code works even if the handler dies
		touchStartTime = 0;
		touchTarget = null;

		if (canTrigger) {
			var newEvent = new MouseEvent('dblclick', ev);
			try {
				ev.target.dispatchEvent(newEvent);
			} catch (e) {
				// don't care, this was complimentary event anyway
			}
		}
	}, false);

});
