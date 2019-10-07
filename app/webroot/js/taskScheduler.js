/*
*
* A JS Task scheduler with flexible task execution strategy
*
*/

(function(){
    if (window.TaskScheduler !== undefined) {
        return; // already defined
    }
    window.TaskScheduler = function(task, config) {
        var default_config = {
            interval: 300, // Interval between each task execution
            slowInterval: 3000, // Interval between each task execution when the task is throttled
            autoThrottle: false, // If the task fails, engage a slow throtlle
            checkboxLink: false, // Link the provided checkbox to the task. The link is done if jQuery object or ID is provided
            container: false, // Insert an HTML switch and link it to the task
            checkboxLabel: '', // The label accompanying the switch
            animation: {
                onExecution: true,
                remainingTime: true,
                noAnimThreshold: 700 //  Animation with interval lower thatn this threshold will not be played 
            }
        };
        this.config = $.extend(true, {}, default_config, config);
        this.task = task;
        this.interval;
        this.taskRunning = false;
        this.backup_parameters = false;
        this.checkbox = false;
        this.init();
        return this;
    };

    TaskScheduler.prototype = {
        constructor: TaskScheduler,

        init: function() {

            if (this.config.container !== false) {
                this.createSwitch();
            }

            if (this.config.checkboxLink !== false) {
                var that = this;
                if (this.config.checkboxLink instanceof jQuery) {
                    var checkbox = this.config.checkboxLink[0];
                } else {
                    var checkbox = document.getElementById(this.config.checkboxLink);
                }
                this.checkbox = checkbox;
                checkbox.addEventListener('change', function() {
                    that.toggle(this.checked);
                });
            }
            this.backup_interval = this.config.interval;
        },

        start: function(arrayParameters) {
            var that = this;
            if (!this.taskRunning) {
                that._start(arrayParameters);
                this.taskRunning = true;
                this.interval = setInterval(function() {
                    that._start(arrayParameters);
                }, this.config.interval);
            }
        },

        _start: function(arrayParameters) {
            this.animate();
            if (arrayParameters !== undefined) {
                this.backup_parameters = arrayParameters;
                this.task.apply(null, arrayParameters);
            } else {
                this.backup_parameters = false;
                this.task();
            }
        },

        stop: function() {
            if (this.taskRunning) {
                this.taskRunning = false;
                clearInterval(this.interval);
            }
        },

        restartTask: function() {
            this.stop();
            if (this.backup_parameters !== false) {
                this.start(this.backup_parameters);
            } else {
                this.start();
            }
        },

        toggle: function(shouldRun, arrayParameters) {
            if (shouldRun) {
                if (arrayParameters !== undefined) {
                    this.start().apply(null, arrayParameters);
                } else {
                    this.start();
                }
            } else {
                this.stop();
            }
        },

        changeInterval: function(newInterval, newSlowInterval) {
            var newConfig = { interval: newInterval };
            if (newSlowInterval !== undefined) {
                newConfig[slowInterval] = newSlowInterval
            }
            this.setConfig(newConfig);
            this.adaptTimeAnimationDuration();
        },

        throttle: function() {
            this.setConfig({interval: this.config.slowInterval });
            this.adaptTimeAnimationDuration();
        },

        unthrottle: function() {
            this.setConfig({interval: this.backup_interval });
            this.adaptTimeAnimationDuration();
        },

        setConfig: function(newConfig) {
            if (this.configHasChanged(newConfig)) {
                this.config = $.extend(true, {}, this.config, newConfig);
                this.restartTask();
            }
        },

        configHasChanged: function(newConfig) {
            var keys = Object.keys(newConfig);
            var value = newConfig[key];
            for (var i = 0; i < keys.length; i++) {
                var key = keys[i];
                var value = newConfig[key];
                if (this.config[key] !== value) {
                    return true;
                }
            }
            return false;
        },

        createSwitch: function() {
            this.container = document.getElementById(this.config.container);
            var temp = document.createElement('div');
            this.config.checkboxLink = this.genRandom();
            var label_id = 'label_' + this.config.checkboxLink;
            var htmlString = '<div class="toggle-switch-wrapper"> \
                                <input type="checkbox" style="display:none" id="' + this.config.checkboxLink + '" checked="checked"> \
                                <label id="' + label_id + '" class="toggle-switch" for="' + this.config.checkboxLink + '"> \
                                    <span class="toggle-switch-handle"><span id="switchTimeRemainig" class="toggle-switch-handle toggle-switch-handle-timer"></span></span> \
                                </label> \
                            </div> \
                            <label class="toggle-switch-label" for="' + this.config.checkboxLink + '"> \
                                <span>' + this.config.checkboxLabel + '</span> \
                            </label>';
            temp.innerHTML = htmlString.trim();
            for (var i = 0; i < temp.childNodes.length; i++) {
                this.container.appendChild(temp.childNodes[i])
            }
            this.label_node = document.getElementById(label_id);
            this.timer_node = this.label_node.getElementsByClassName('toggle-switch-handle-timer')[0];
            this.adaptTimeAnimationDuration();
        },

        adaptTimeAnimationDuration: function() {
            // 200ms offset applied to try to avoid race condition with the class removal
            this.timer_node.style['animation-duration'] = ((this.config.interval-200) / 1000).toFixed(2) + 's';
            this.timer_node.title = 'Executing task every ' + ((this.config.interval) / 1000).toFixed(2) + 's';
        },

        animate: function() {
            var that = this;
            if (this.config.interval < this.config.animation.noAnimThreshold) {
                return;
            }
            if (this.config.animation.onExecution) {
                this.label_node.classList.add('toggle-switch-animate-execution');
                this.prefixedEventListener(this.label_node, "AnimationEnd", function() {
                    that.label_node.classList.remove('toggle-switch-animate-execution');
                });
            }
            if (this.config.animation.remainingTime) {
                this.timer_node.classList.add('toggle-switch-animate-time-remaining');
                this.prefixedEventListener(this.timer_node, "AnimationEnd", function() {
                    that.timer_node.classList.remove('toggle-switch-animate-time-remaining');
                });
            }
        },

        genRandom: function() {
            return Math.random().toString(36).substr(2,9);
        },

        // Animation-* is vendor specific
        // https://www.sitepoint.com/css3-animation-javascript-event-handlers/
        prefixedEventListener: function (element, eventType, callback) {
            var pfx = ["webkit", "moz", "MS", "o", ""];
            for (var p = 0; p < pfx.length; p++) {
                if (!pfx[p]) {
                    eventType = eventType.toLowerCase();
                }
                element.addEventListener(pfx[p]+eventType, callback, false);
            }
        }
    }
}());
