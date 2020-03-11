/*
*
* A JS Task scheduler with flexible task execution strategy
*
*/

// ! Checkbox do not exists anymore due to page reload
// Why doesnt the task stop

(function(){
    if (window.TaskScheduler !== undefined) {
        return; // already defined
    }
    window.TaskScheduler = function(task, config) {
        var default_config = {
            interval: 300,                  // Interval between each task execution
            slowInterval: 3000,             // Interval between each task execution when the task is throttled
            autoThrottle: false,            // If the task fails (i.e. return false), engage a slow throtlle - WIP
            checkboxLink: false,            // Link the provided checkbox to the task. The link is done if jQuery object or ID is provided
            container: false,               // Insert an HTML switch and link it to the task
            checkboxLabel: '',              // The label accompanying the switch
            animation: {
                onExecution: true,          // Perform an animation whenever the task is being run
                remainingTime: false,       // Perfim an animation showing how much time is needed for the next task run
                noAnimThreshold: 700        //  Animation with interval lower thatn this threshold will not be played 
            }
        };
        this.config = $.extend(true, {}, default_config, config);
        this.task = task;
        this.interval;
        this.taskRunning = false;
        this.taskScheduled = false;
        this.cancelRequested = false;
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
                if (this.config.checkboxLink instanceof jQuery) {
                    this.checkbox = this.config.checkboxLink[0];
                } else {
                    this.checkbox = document.getElementById(this.config.checkboxLink);
                }
                this.registerListeners();
            }
            this.backup_interval = this.config.interval;
        },

        start: function(arrayParameters, immediate) {
            immediate = immediate === undefined ? true  : immediate;
            var that = this;
            if (!this.taskRunning) {
                if (!this.checkbox.checked) {
                    this.checkbox.checked = true;
                }
                this.taskRunning = true;
                if (immediate) {
                    that._start(arrayParameters);
                }
                this.taskScheduled = true;
                this.interval = setInterval(function() {
                    this.taskScheduled = false;
                    that._start(arrayParameters);
                }, this.config.interval);
            }
        },

        _start: function(arrayParameters) {
            if (this.cancelRequested) {
                this.cancelRequested = false;
                return;
            }
            this.animate();
            this.adaptTimeAnimationDuration(false);
            var taskResult = true;
            if (arrayParameters !== undefined) {
                this.backup_parameters = arrayParameters;
                taskResult = this.task.apply(null, arrayParameters);
            } else {
                this.backup_parameters = false;
                taskResult = this.task();
            }
            if (this.config.autoThrottle) {
                if (taskResult === false) {
                    this.throttle();
                } else if (taskResult === true) {
                    this.unthrottle();
                }
            }
        },

        stop: function() {
            if (this.taskRunning) {
                if (this.checkbox.checked) {
                    this.checkbox.checked = false;
                }
                this.taskRunning = false;
                this._removeAnimation();
                this.adaptTimeAnimationDuration(true);
                clearInterval(this.interval);
            }
        },

        cancel: function() {
            if (this.taskScheduled) {
                this.cancelRequested = true;
            }
        },

        restartTask: function(immediate) {
            immediate = immediate === undefined ? true  : immediate;
            this.stop();
            if (this.backup_parameters !== false) {
                this.start(this.backup_parameters, immediate);
            } else {
                this.start(undefined, immediate);
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
                this.restartTask(false);
            }
        },

        configHasChanged: function(newConfig) {
            var keys = Object.keys(newConfig);
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
            var checked = this.taskScheduled;
            this.container = document.getElementById(this.config.container);
            if (this.container === undefined || this.container === null) {
                throw "Cannot create switch. Container does not exists";
            }
            var temp = document.createElement('div');
            this.config.checkboxLink = this.genRandom();
            var label_id = 'label_' + this.config.checkboxLink;
            var htmlString = '<div class="toggle-switch-wrapper"> \
                                <input type="checkbox" style="display:none" id="' + this.config.checkboxLink + '" ' + (checked ? 'checked="checked"' : '') + '> \
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
            this.checkbox = document.getElementById(this.config.checkboxLink);
            this.adaptTimeAnimationDuration();
            this.registerListeners();
        },

        registerListeners: function() {
            var that = this;
            this.checkbox.addEventListener('change', function() {
                that.toggle(this.checked);
            });
        },

        adaptTimeAnimationDuration: function(disabled) {
            if (disabled === true) {
                this.label_node.title = 'Task not scheduled';
            } else {
                // 200ms offset applied to try to avoid race condition with the class removal
                this.timer_node.style['animation-duration'] = ((this.config.interval-200) / 1000).toFixed(2) + 's';
                this.label_node.title = 'Executing task every ' + ((this.config.interval) / 1000).toFixed(2) + 's';
            }
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

        _removeAnimation: function() {
            this.label_node.classList.remove('toggle-switch-animate-execution');
            this.timer_node.classList.remove('toggle-switch-animate-time-remaining');
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
