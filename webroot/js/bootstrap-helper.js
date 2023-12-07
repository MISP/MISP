/** Class containing common UI functionalities */
class UIFactory {
    /**
     * Create and display a toast
     * @param  {Object} options - The options to be passed to the Toaster class
     * @return {Object} The Toaster object
     */
    toast(options) {
        const theToast = new Toaster(options);
        theToast.makeToast()
        theToast.show()
        return theToast
    }

    /**
     * Create and display a modal
     * @param  {Object} options - The options to be passed to the ModalFactory class
     * @return {Object} The ModalFactory object
     */
    modal(options) {
        const theModal = new ModalFactory(options);
        theModal.makeModal()
        theModal.show()
        return theModal
    }

    /**
     * Create a popover
     * @param  {Object} element - The target element on which to attach the popover
     * @param  {Object} options - The options to be passed to the PopoverFactory class
     * @return {Object} The PopoverFactory object
     */
    popover(element, options) {
        const thePopover = new PopoverFactory(element, options);
        thePopover.makePopover()
        return thePopover
    }

    /**
     * Create and display a modal where the modal's content is fetched from the provided URL. Link an AJAXApi to the submission button
     * @param  {string} url - The URL from which the modal's content should be fetched
     * @param  {ModalFactory~POSTSuccessCallback} POSTSuccessCallback - The callback that handles successful form submission
     * @param  {ModalFactory~POSTFailCallback} POSTFailCallback - The callback that handles form submissions errors and validation errors.
     * @param  {Object=[]} modalOptions - Additional options to be passed to the modal constructor
     * @return {Promise<Object>} Promise object resolving to the ModalFactory object
     */
    async submissionModal(url, POSTSuccessCallback, POSTFailCallback, modalOptions={}) {
        return AJAXApi.quickFetchURL(url).then((modalHTML) => {
            const defaultOptions = {
                rawHtml: modalHTML,
                POSTSuccessCallback: POSTSuccessCallback !== undefined ? POSTSuccessCallback : () => {},
                POSTFailCallback: POSTFailCallback !== undefined ? POSTFailCallback : (errorMessage) => {},
            }
            const options = Object.assign({}, defaultOptions, modalOptions)
            const theModal = new ModalFactory(options);
            theModal.makeModal()
            theModal.show()
            theModal.$modal.data('modalObject', theModal)
            return [theModal, theModal.ajaxApi]
        }).catch((error) => {
            UI.toast({
                variant: 'danger',
                title: 'Error while loading the modal',
                body: error.message
            })
        })
    }

    /**
     * Create and display a modal where the modal's content is fetched from the provided URL
     * @param  {string} url - The URL from which the modal's content should be fetched
     * @param  {Object=[]} modalOptions - Additional options to be passed to the modal constructor
     * @return {Promise<Object>} Promise object resolving to the ModalFactory object
     */
    async modalFromUrl(url, modalOptions={}) {
        return AJAXApi.quickFetchURL(url).then((modalHTML) => {
            const defaultOptions = {
                rawHtml: modalHTML,
            }
            const options = Object.assign({}, defaultOptions, modalOptions)
            const theModal = new ModalFactory(options);
            theModal.makeModal()
            theModal.show()
            theModal.$modal.data('modalObject', theModal)
            return [theModal, theModal.ajaxApi]
        }).catch((error) => {
            UI.toast({
                variant: 'danger',
                title: 'Error while loading the modal',
                body: error.message
            })
        })
    }

    /**
     * Creates and displays a modal where the modal's content is fetched from the provided URL. Reloads the single page view after a successful operation.
     * Supports `displayOnSuccess` option to show another modal after the submission
     * @param  {string} url - The URL from which the modal's content should be fetched
     * @param  {(boolean|string)} [reloadUrl=false] - The URL from which the data should be fetched after confirming
     * @param  {(jQuery|string)} [$table=false] - The table ID which should be reloaded on success
     * @return {Promise<Object>} Promise object resolving to the ModalFactory object
     */
    submissionModalForSinglePage(url, reloadUrl=false, $table=false) {
        let $statusNode, $reloadedElement
        if (reloadUrl === false) {
            reloadUrl = location.pathname
        }
        if ($table === false) { // Try to get information from the DOM
            const $elligibleTable = $('table[id^="single-view-table-"]')
            const $container = $elligibleTable.closest('div[id^="single-view-table-container-"]')
            $reloadedElement = $container
            $statusNode = $elligibleTable
        } else {
            if ($table instanceof jQuery) {
                $reloadedElement = $table
                $statusNode = $table.find('table[id^="single-view-table-"]')
            } else {
                $reloadedElement = $(`single-view-table-container-${$table}`)
                $statusNode = $(`single-view-table-${$table}`)
            }
        }
        if ($reloadedElement.length == 0) {
            UI.toast({
                variant: 'danger',
                title: 'Could not find element to be reloaded',
                body: 'The content of this page may have changed and has not been reflected. Reloading the page is advised.'
            })
            return
        }
        return UI.submissionReloaderModal(url, reloadUrl, $reloadedElement, $statusNode);
    }

    getContainerForTable($table) {
        const tableRandomID = $table.data('table-random-value')
        return $table.closest(`#table-container-${tableRandomID}`)
    }

    /**
     * Creates and displays a modal where the modal's content is fetched from the provided URL. Reloads the index table after a successful operation.
     * Supports `displayOnSuccess` option to show another modal after the submission
     * @param  {string} url - The URL from which the modal's content should be fetched
     * @param  {(boolean|string)} [reloadUrl=false] - The URL from which the data should be fetched after confirming
     * @param  {(jQuery|string)} [$table=false] - The table ID which should be reloaded on success
     * @return {Promise<Object>} Promise object resolving to the ModalFactory object
     */
    submissionModalForIndex(url, reloadUrl=false, $table=false) {
        let $statusNode, $reloadedElement
        if (reloadUrl === false) {
            const currentModel = location.pathname.split('/')[1]
            if (currentModel.length > 0) {
                reloadUrl = `/${currentModel}/index`
            } else {
                UI.toast({
                    variant: 'danger',
                    title: 'Could not find URL for the reload',
                    body: 'The content of this page may have changed and has not been reflected. Reloading the page is advised.'
                })
                return
            }
        }
        if ($table === false) { // Try to get information from the DOM
            const $elligibleTable = $('table.table')
            const $container = $elligibleTable.closest('div[id^="table-container-"]')
            $reloadedElement = $container
            $statusNode = $elligibleTable
        } else {
            if ($table instanceof jQuery) {
                $reloadedElement = this.getContainerForTable($table)
                $statusNode = $table.find('table.table')
            } else {
                $reloadedElement = $(`#table-container-${$table}`)
                $statusNode = $(`#table-container-${$table} table.table`)
            }
        }
        if ($reloadedElement.length == 0) {
            UI.toast({
                variant: 'danger',
                title: 'Could not find element to be reloaded',
                body: 'The content of this page may have changed and has not been reflected. Reloading the page is advised.'
            })
            return
        }
        return UI.submissionReloaderModal(url, reloadUrl, $reloadedElement, $statusNode);
    }

    /**
     * Creates and displays a modal where the modal's content is fetched from the provided URL. Reloads the index table after a successful operation.
     * Supports `displayOnSuccess` option to show another modal after the submission
     * @param  {string} url - The URL from which the modal's content should be fetched
     * @param  {(boolean|string)} [reloadUrl=false] - The URL from which the data should be fetched after confirming
     * @param  {(jQuery|string)} [$table=false] - The table ID which should be reloaded on success
     * @return {Promise<Object>} Promise object resolving to the ModalFactory object
     */
    submissionModalAutoGuess(url, reloadUrl=false, $table=false) {
        const explodedLocation = location.pathname.split('/').filter((i) => i.length > 0)
        let currentAction = explodedLocation[1]
        if (explodedLocation.length == 1 && currentAction === undefined) {
            currentAction = 'index'
        }
        if (currentAction !== undefined) {
            if (currentAction === 'index') {
                return UI.submissionModalForIndex(url, reloadUrl, $table)
            } else if (currentAction === 'view') {
                return UI.submissionModalForSinglePage(url, reloadUrl, $table)
            }
        }
        const successCallback = () => {
                UI.toast({
                variant: 'danger',
                title: 'Could not reload the page',
                body: 'Reloading the page manually is advised.'
            })
        }
        return UI.submissionModal(url, successCallback)
    }

    /**
     * Creates and displays a modal where the modal's content is fetched from the provided URL. Reloads the provided element after a successful operation.
     * Supports `displayOnSuccess` option to show another modal after the submission
     * @param  {string} url - The URL from which the modal's content should be fetched
     * @param  {string} reloadUrl - The URL from which the data should be fetched after confirming
     * @param  {(jQuery|string)} $reloadedElement - The element which should be reloaded on success
     * @param  {(jQuery|string)} [$statusNode=null] - A reference to a HTML node on which the loading animation should be displayed. If not provided, $container will be used
     * @return {Promise<Object>} Promise object resolving to the ModalFactory object
     */
    submissionReloaderModal(url, reloadUrl, $reloadedElement, $statusNode=null) {
        const successCallback = function ([data, modalObject]) {
            UI.reload(reloadUrl, $reloadedElement, $statusNode)
            if (data.additionalData !== undefined) {
                if (data.additionalData.displayOnSuccess !== undefined) {
                    UI.modal({
                        rawHtml: data.additionalData.displayOnSuccess
                    })
                } else if (data.additionalData.redirect !== undefined) {
                    window.location = data.additionalData.redirect
                }
            }
        }
        return UI.submissionModal(url, successCallback)
    }

    /**
     * Fetch HTML from the provided URL and override the $container's content. $statusNode allows to specify another HTML node to display the loading
     * @param  {string} url - The URL from which the $container's content should be fetched
     * @param  {(jQuery|string)} $container - The container that should hold the data fetched
     * @param  {(jQuery|string)} [$statusNode=null] - A reference to a HTML node on which the loading animation should be displayed. If not provided, $container will be used
     * @param  {array} [additionalStatusNodes=[]] - A list of other node on which to apply overlay. Must contain the node and possibly the overlay configuration
     * @return {Promise<jQuery>} Promise object resolving to the $container object after its content has been replaced
     */
    reload(url, $container, $statusNode=null, additionalStatusNodes=[]) {
        $container = $($container)
        $statusNode = $($statusNode)
        if (!$statusNode) {
            $statusNode = $container
        }
        const otherStatusNodes = []
        additionalStatusNodes.forEach(otherStatusNode => {
            const loadingOverlay = new OverlayFactory(otherStatusNode.node, otherStatusNode.config)
            loadingOverlay.show()
            otherStatusNodes.push(loadingOverlay)
        })
        return AJAXApi.quickFetchURL(url, {
            statusNode: $statusNode[0],
        }).then((theHTML) => {
            var $tmp = $(theHTML);
            $container.replaceWith($tmp)
            return $tmp;
        }).finally(() => {
            otherStatusNodes.forEach(overlay => {
                overlay.hide()
            })
        })
    }

    /**
     * Place an overlay onto a node and remove it whenever the promise resolves
     * @param {(jQuery|string)} node       - The node on which the overlay should be placed
     * @param {Promise} promise            - A promise to be fulfilled
     * @param {Object} [overlayOptions={}  - The options to be passed to the overlay class
     * @return {Promise} Result of the passed promised
     */
    overlayUntilResolve(node, promise, overlayOptions={}) {
        const $node = $(node)
        const loadingOverlay = new OverlayFactory($node[0], overlayOptions);
        loadingOverlay.show()
        promise.finally(() => {
            loadingOverlay.hide()
        })
        return promise
    }

    /**
     * Place an overlay onto a node and remove it whenever the promise resolves
     * @param {(jQuery|string)} node       - The node on which the confirm popover should be palced
     * @param {Object} options             - The options to be passed to the overlay class
     * @return {Promise} Result of the passed promised
     */
    quickConfirm(node, options={}) {
        const $node = $(node)
        const defaultOptions = {
            title: 'Confirm action',
            description: '',
            descriptionHtml: false,
            container: 'body',
            variant: 'success',
            confirmText: 'Confirm',
            confirm: function() {}
        }
        options = Object.assign({}, defaultOptions, options)
        options.description = options.descriptionHtml ? options.descriptionHtml : sanitize(options.description)
        const popoverOptions = {
            title: options.title,
            titleHtml: options.titleHtml,
            container: options.container,
            html: true,
        }

        var promiseResolve, promiseReject;
        const confirmPromise = new Promise(function (resolve, reject) {
            promiseResolve = resolve;
            promiseReject = reject;
        })
        popoverOptions.content = function() {
            const $node = $(this)
            const $container = $('<div>')
            const $buttonCancel = $('<a class="btn btn-secondary btn-sm me-2">Cancel</a>')
                .click(function() {
                    const popover = bootstrap.Popover.getInstance($node[0])
                    popover.dispose()
                })
            const $buttonSubmit = $(`<a class="submit-button btn btn-${options.variant} btn-sm">${options.confirmText}</a>`)
                .click(function() {
                    options.confirm()
                        .then(function(result) {
                            promiseResolve(result)
                        })
                        .catch(function(error) {
                            promiseReject(error)
                        })
                    const popover = bootstrap.Popover.getInstance($node[0])
                    popover.dispose()
                })
            $container.append(`<p>${options.description}</p>`)
            $container.append($(`<div>`).append($buttonCancel, $buttonSubmit))
            return $container
        }

        const thePopover = this.popover($node, popoverOptions)
        thePopover.show()
        return confirmPromise // have to return a promise to avoid closing the modal
    }
}

/** Class representing a Toast */
class Toaster {
    /**
     * Create a Toast.
     * @param  {Object} options - The options supported by Toaster#defaultOptions
     */
    constructor(options) {
        this.options = Object.assign({}, Toaster.defaultOptions, options)
        if (this.options.delay == 'auto') {
            this.options.delay = this.computeDelay()
        }
        this.bsToastOptions = {
            autohide: this.options.autohide,
            delay: this.options.delay,
        }
    }

    /**
     * @namespace
     * @property {number}  id           - The ID to be used for the toast's container
     * @property {string}  title        - The title's content of the toast
     * @property {string}  muted        - The muted's content of the toast
     * @property {string}  body         - The body's content of the toast
     * @property {string=('primary'|'secondary'|'success'|'danger'|'warning'|'info'|'light'|'dark'|'white'|'transparent')} variant - The variant of the toast
     * @property {boolean} autohide    - If the toast show be hidden after some time defined by the delay
     * @property {(number|string)}  delay        - The number of milliseconds the toast should stay visible before being hidden or 'auto' to deduce the delay based on the content
     * @property {(jQuery|string)}  titleHtml    - The raw HTML title's content of the toast
     * @property {(jQuery|string)}  mutedHtml    - The raw HTML muted's content of the toast
     * @property {(jQuery|string)}  bodyHtml     - The raw HTML body's content of the toast
     * @property {boolean} closeButton - If the toast's title should include a close button
     */
    static defaultOptions = {
        id: false,
        title: false,
        muted: false,
        body: false,
        variant: 'default',
        autohide: true,
        delay: 'auto',
        titleHtml: false,
        mutedHtml: false,
        bodyHtml: false,
        closeButton: true,
    }

    /** Create the HTML of the toast and inject it into the DOM */
    makeToast() {
        if (this.isValid()) {
            this.$toast = Toaster.buildToast(this.options)
            this.$toast.data('toastObject', this)
            $('#mainToastContainer').append(this.$toast)
        }
    }

    /** Display the toast to the user and remove it from the DOM once it get hidden */
    show() {
        if (this.isValid()) {
            var that = this
            this.$toast.toast(this.bsToastOptions)
                .toast('show')
                .on('hide.bs.toast', function (evt) {
                    const $toast = $(this)
                    const hoveredElements = $(':hover').filter(function() {
                        return $(this).is($toast)
                    });
                    if (hoveredElements.length > 0) {
                        evt.preventDefault()
                        setTimeout(() => {
                            $toast.toast('hide')
                        }, that.options.delay);
                    }
                })
                .on('hidden.bs.toast', function () {
                    that.removeToast()
                })
        }
    }

    /** Remove the toast from the DOM */
    removeToast() {
        this.$toast.remove();
    }

    /**
     * Check wheter a toast is valid
     * @return {boolean} Return true if the toast contains at least data to be rendered
     */
    isValid() {
        return this.options.title !== false || this.options.titleHtml !== false ||
        this.options.muted !== false || this.options.mutedHtml !== false ||
        this.options.body !== false || this.options.bodyHtml !== false
    }

    /**
     * Build the toast HTML
     * @param {Object} options - The options supported by Toaster#defaultOptions to build the toast
     * @return {jQuery} The toast jQuery object
     */
    static buildToast(options) {
        var $toast = $('<div class="toast" role="alert" aria-live="assertive" aria-atomic="true"/>')
        if (options.id !== false) {
            $toast.attr('id', options.id)
        }
        $toast.addClass('toast-' + options.variant)
        if (options.title !== false || options.titleHtml !== false || options.muted !== false || options.mutedHtml !== false || options.closeButton) {
            var $toastHeader = $('<div class="toast-header"/>')
            $toastHeader.addClass('toast-' + options.variant)
            let $toastHeaderText = $('<span class="me-auto"/>')
            if (options.titleHtml !== false) {
                $toastHeaderText = $('<div class="me-auto"/>').html(options.titleHtml);
            } else if (options.title !== false) {
                $toastHeaderText = $('<strong class="me-auto"/>').text(options.title)
            }
            $toastHeader.append($toastHeaderText)
            if (options.muted !== false || options.mutedHtml !== false) {
                var $toastHeaderMuted
                if (options.mutedHtml !== false) {
                    $toastHeaderMuted = $('<div/>').html(options.mutedHtml)
                } else {
                    $toastHeaderMuted = $('<small class="text-muted"/>').text(options.muted)
                }
                $toastHeader.append($toastHeaderMuted)
            }
            if (options.closeButton) {
                var $closeButton = $('<button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>')
                    .click(function() {
                        $(this).closest('.toast').data('toastObject').removeToast()
                    })
                $toastHeader.append($closeButton)
            }
            $toast.append($toastHeader)
        }
        if (options.body !== false || options.bodyHtml !== false) {
            var $toastBody
            if (options.bodyHtml !== false) {
                $toastBody = $('<div class="toast-body"/>').html(options.bodyHtml)
            } else {
                $toastBody = $('<div class="toast-body"/>').append($('<div style="white-space: break-spaces;"/>').text(options.body))
            }
            $toast.append($toastBody)
        }
        return $toast
    }

    computeDelay() {
        return 3000
            + 40*((this.options.title?.length ?? 0) + (this.options.body?.length ?? 0))
            + (['danger', 'warning'].includes(this.options.variant) ? 5000 : 0)
    }
}

/** Class representing a Modal */
class ModalFactory {
    /**
     * Create a Modal.
     * @param  {Object} options - The options supported by ModalFactory#defaultOptions
     */
    constructor(options) {
        this.options = Object.assign({}, ModalFactory.defaultOptions, options)
        if (options.POSTSuccessCallback !== undefined) {
            if (!this.options.rawHtml) {
                UI.toast({
                    variant: 'danger',
                    bodyHtml: '<b>POSTSuccessCallback</b> can only be used in conjuction with the <i>rawHtml</i> option. Instead, use the promise instead returned by the API call in <b>APIConfirm</b>.'
                })
            }
        }
        if (this.options.rawHtml) {
            this.attachSubmitButtonListener = true
        }
        if (options.type === undefined && options.cancel !== undefined) {
            this.options.type = 'confirm'
        }
        this.bsModalOptions = {
            show: true
        }
        if (this.options.backdropStatic) {
            this.bsModalOptions['backdrop'] = 'static'
        }
        this.ajaxApi = new AJAXApi()
    }

    /**
     * @callback ModalFactory~closeModalFunction
     */
    /**
     * @callback ModalFactory~confirm
     * @param {ModalFactory~confirm} closeFunction - A function that will close the modal if called
     * @param {Object} modalFactory - The instance of the ModalFactory
     * @param {Object} evt - The event that triggered the confirm operation
     */
    /**
     * @callback ModalFactory~cancel
     * @param {ModalFactory~cancel} closeFunction - A function that will close the modal if called
     * @param {Object} modalFactory - The instance of the ModalFactory
     * @param {Object} evt - The event that triggered the confirm operation
     */
    /**
     * @callback ModalFactory~APIConfirm
     * @param {AJAXApi} ajaxApi - An instance of the AJAXApi with the AJAXApi.statusNode linked to the modal confirm button
     */
    /**
     * @callback ModalFactory~APIError
     * @param {ModalFactory~closeModalFunction} closeFunction - A function that will close the modal if called
     * @param {Object} modalFactory - The instance of the ModalFactory
     * @param {Object} evt - The event that triggered the confirm operation
     */
    /**
     * @callback ModalFactory~shownCallback
     * @param {Object} modalFactory - The instance of the ModalFactory
     */
    /**
     * @callback ModalFactory~hiddenCallback
     * @param {Object} modalFactory - The instance of the ModalFactory
     */
    /**
     * @callback ModalFactory~POSTSuccessCallback
     * @param {Object} data - The data received from the successful POST operation
     */
    /**
     * @callback ModalFactory~POSTFailCallback
     * @param {string} errorMessage
     */
    /**
     * @namespace
     * @property {number} id                               - The ID to be used for the modal's container
     * @property {string=('sm'|'lg'|'xl'|'')} size         - The size of the modal
     * @property {boolean} centered                        - Should the modal be vertically centered
     * @property {boolean} scrollable                      - Should the modal be scrollable
     * @property {boolean} backdropStatic                  - When set, the modal will not close when clicking outside it.
     * @property {string} title                            - The title's content of the modal
     * @property {string} titleHtml                        - The raw HTML title's content of the modal
     * @property {string} body                             - The body's content of the modal
     * @property {string} bodyHtml                         - The raw HTML body's content of the modal
     * @property {string} rawHtml                          - The raw HTML of the whole modal. If provided, will override any other content
     * @property {string=('primary'|'secondary'|'success'|'danger'|'warning'|'info'|'light'|'dark'|'white'|'transparent')} variant - The variant of the modal
     * @property {string} modalClass                       - Classes to be added to the modal's container
     * @property {string} headerClass                      - Classes to be added to the modal's header
     * @property {string} bodyClass                        - Classes to be added to the modal's body
     * @property {string} footerClass                      - Classes to be added to the modal's footer
     * @property {string=('ok-only','confirm','confirm-success','confirm-warning','confirm-danger')} type - Pre-configured template covering most use cases
     * @property {string} confirmText                      - The text to be placed in the confirm button
     * @property {string} cancelText                       - The text to be placed in the cancel button
     * @property {boolean} closeManually                   - If true, the modal will be closed automatically whenever a footer's button is pressed
     * @property {boolean} closeOnSuccess                  - If true, the modal will be closed if the operation is successful
     * @property {ModalFactory~confirm} confirm                         - The callback that should be called if the user confirm the modal
     * @property {ModalFactory~cancel} cancel                           - The callback that should be called if the user cancel the modal
     * @property {ModalFactory~APIConfirm} APIConfirm                   - The callback that should be called if the user confirm the modal. Behaves like the confirm option but provides an AJAXApi object that can be used to issue requests
     * @property {ModalFactory~APIError} APIError                       - The callback called if the APIConfirm callback fails.
     * @property {ModalFactory~shownCallback} shownCallback             - The callback that should be called whenever the modal is shown
     * @property {ModalFactory~hiddenCallback} hiddenCallback           - The callback that should be called whenever the modal is hiddenAPIConfirm
     * @property {ModalFactory~POSTSuccessCallback} POSTSuccessCallback - The callback that should be called if the POST operation has been a success. Works in confunction with the `rawHtml`
     * @property {ModalFactory~POSTFailCallback} POSTFailCallback       - The callback that should be called if the POST operation has been a failure (Either the request failed or the form validation did not pass)
     */
    static defaultOptions = {
        id: false,
        size: 'md',
        centered: false,
        scrollable: false,
        backdropStatic: false,
        title: '',
        titleHtml: false,
        body: false,
        bodyHtml: false,
        rawHtml: false,
        variant: '',
        modalClass: '',
        headerClass: '',
        bodyClass: '',
        footerClass: '',
        type: 'ok-only',
        confirmText: 'Confirm',
        cancelText: 'Cancel',
        closeManually: false,
        closeOnSuccess: true,
        confirm: function() {},
        cancel: function() {},
        APIConfirm: null,
        APIError: function() {},
        shownCallback: function() {},
        hiddenCallback: function() {},
        POSTSuccessCallback: function() {},
        POSTFailCallback: function() {},
    }

    static availableType = [
        'ok-only',
        'confirm',
        'confirm-success',
        'confirm-warning',
        'confirm-danger',
    ]

    static closeButtonHtml = '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>'

    /** Create the HTML of the modal and inject it into the DOM */
    makeModal() {
        if (this.isValid()) {
            this.$modal = this.buildModal()
            $('#mainModalContainer').append(this.$modal)
            this.modalInstance = new bootstrap.Modal(this.$modal[0], this.bsModalOptions)
        } else {
            console.log('Modal not valid')
        }
    }

    /** Display the modal and remove it form the DOM once it gets hidden */
    show() {
        if (this.isValid()) {
            var that = this
            this.modalInstance.show()
            this.$modal
                .on('hidden.bs.modal', function () {
                    that.removeModal()
                    that.options.hiddenCallback(that)
                })
                .on('shown.bs.modal', function () {
                    that.options.shownCallback(that)
                    if (that.attachSubmitButtonListener) {
                        that.findSubmitButtonAndAddListener()
                    }
                })
            // this.$modal.modal(this.bsModalOptions)
            //     .on('hidden.bs.modal', function () {
            //         that.removeModal()
            //         that.options.hiddenCallback(that)
            //     })
            //     .on('shown.bs.modal', function () {
            //         that.options.shownCallback(that)
            //         if (that.attachSubmitButtonListener) {
            //             that.findSubmitButtonAndAddListener()
            //         }
            //     })
        } else {
            console.log('Modal not valid')
        }
    }

    /** Hide the modal using the bootstrap modal's hide command */
    hide() {
        // this.$modal.modal('hide')
        this.modalInstance.hide()
    }
    
    /** Remove the modal from the DOM */
    removeModal() {
        this.$modal.remove();
    }

    /**
     * Check wheter a modal is valid
     * @return {boolean} Return true if the modal contains at least data to be rendered
     */
    isValid() {
        return this.options.title !== false || this.options.titleHtml !== false ||
        this.options.body !== false ||  this.options.bodyHtml !== false ||
        this.options.rawHtml !== false
    }

    /**
     * Build the modal HTML
     * @return {jQuery} The modal jQuery object
     */
    buildModal() {
        const $modal = $('<div class="modal fade" tabindex="-1"/>')
        if (this.options.id !== false) {
            $modal.attr('id', this.options.id)
            $modal.attr('aria-labelledby', this.options.id)
        }
        if (this.options.modalClass) {
            $modal.addClass(this.options.modalClass)
        }
        let $modalDialog
        if (this.options.rawHtml) {
            $modalDialog = $(this.options.rawHtml)
            if ($modalDialog.data('backdrop') == 'static') {
                this.bsModalOptions['backdrop'] = 'static'
            }
        } else {
            $modalDialog = $('<div class="modal-dialog"/>')
            if (this.options.size !== false) {
                $modalDialog.addClass(`modal-${this.options.size}`)
            }
            const $modalContent = $('<div class="modal-content"/>')
            if (this.options.title !== false || this.options.titleHtml !== false) {
                const $modalHeader = $('<div class="modal-header"/>')
                if (this.options.headerClass) {
                    $modalHeader.addClass(this.options.headerClass)
                }
                let $modalHeaderText
                if (this.options.titleHtml !== false) {
                    $modalHeaderText = $('<div/>').html(this.options.titleHtml);
                } else {
                    $modalHeaderText = $('<h5 class="modal-title"/>').text(this.options.title)
                }
                $modalHeader.append($modalHeaderText, ModalFactory.getCloseButton())
                $modalContent.append($modalHeader)
            }
    
            if (this.options.body !== false || this.options.bodyHtml !== false) {
                const $modalBody = $('<div class="modal-body"/>')
                if (this.options.bodyClass) {
                    $modalBody.addClass(this.options.bodyClass)
                }
                let $modalBodyText
                if (this.options.bodyHtml !== false) {
                    $modalBodyText = $('<div/>').html(this.options.bodyHtml);
                } else {
                    $modalBodyText = $('<div/>').text(this.options.body)
                }
                $modalBody.append($modalBodyText)
                $modalContent.append($modalBody)
            }
    
            const $modalFooter = $('<div class="modal-footer"/>')
            if (this.options.footerClass) {
                $modalFooter.addClass(this.options.footerClass)
            }
            $modalFooter.append(this.getFooterBasedOnType())
            $modalContent.append($modalFooter)
    
            $modalDialog.append($modalContent)
        }
        $modal.append($modalDialog)
        return $modal
    }

    /** Returns the correct footer data based on the provided type */
    getFooterBasedOnType() {
        if (this.options.type == 'ok-only') {
            return this.getFooterOkOnly()
        } else if (this.options.type.includes('confirm')) {
            return this.getFooterConfirm()
        } else {
            return this.getFooterOkOnly()
        }
    }

    /** Generate the ok-only footer type */
    getFooterOkOnly() {
        return [
            $('<button type="button" class="btn btn-primary">OK</button>')
                .attr('data-bs-dismiss', 'modal'),
        ]
    }

    /** Generate the confirm-* footer type */
    getFooterConfirm() {
        let variant = this.options.type.split('-')[1]
        variant = variant !== undefined ? variant : 'primary'
        const $buttonCancel = $('<button type="button" class="btn btn-secondary" data-bs-dismiss="modal"></button>')
                .text(this.options.cancelText)
                .click(
                    (evt) => {
                        this.options.cancel(() => { this.hide() }, this, evt)
                    }
                )
                .attr('data-bs-dismiss', (this.options.closeManually || !this.options.closeOnSuccess) ? '' : 'modal')

        const $buttonConfirm = $('<button type="button" class="btn"></button>')
                .addClass('btn-' + variant)
                .text(this.options.confirmText)
                .attr('data-bs-dismiss', (this.options.closeManually || this.options.closeOnSuccess) ? '' : 'modal')
        $buttonConfirm.click(this.getConfirmationHandlerFunction($buttonConfirm))
        return [$buttonCancel, $buttonConfirm]
    }

    /** Return a close button */
    static getCloseButton() {
        return $(ModalFactory.closeButtonHtml)
    }

    /** Generate the function that will be called when the user confirm the modal */
    getConfirmationHandlerFunction($buttonConfirm, buttonIndex) {
        if (this.options.APIConfirms) {
            if (Array.isArray(this.ajaxApi)) {
                const tmpApi = new AJAXApi({
                    statusNode: $buttonConfirm[0]
                })
                this.ajaxApi.push(tmpApi)
            } else {
                this.ajaxApi.options.statusNode = $buttonConfirm[0]
                this.ajaxApi = [this.ajaxApi];
            }
        } else {
            this.ajaxApi.options.statusNode = $buttonConfirm[0]
        }
        return (evt) => {
            let confirmFunction = this.options.confirm
            if (this.options.APIConfirms) {
                if (buttonIndex !== undefined && this.options.APIConfirms[buttonIndex] !== undefined) {
                    confirmFunction = () => { return this.options.APIConfirms[buttonIndex](this.ajaxApi[buttonIndex]) }
                }
            } else if (this.options.APIConfirm) {
                confirmFunction = () => { return this.options.APIConfirm(this.ajaxApi) }
            }
            let confirmResult = confirmFunction(() => { this.hide() }, this, evt)
            if (confirmResult === undefined) {
                this.hide()
            } else {
                confirmResult.then((data) => {
                    if (this.options.closeOnSuccess) {
                        this.hide()
                    }
                })
                .catch((err) => {
                    this.options.APIError(() => { this.hide() }, this, evt)
                })
            }
        }
    }

    /** Attach the submission click listener for modals that have been generated by raw HTML */
    findSubmitButtonAndAddListener() {
        let $modalFooter = this.$modal.find('.modal-footer')
        if ($modalFooter.data('custom-footer')) { // setup basic listener as callback are defined in the template
            let $submitButtons = this.$modal.find('.modal-footer .modal-confirm-button')
            var selfModal = this;
            selfModal.options.APIConfirms = [];
            $submitButtons.each(function(i) {
                const $submitButton = $(this)
                if ($submitButton.data('clickfunction') !== undefined && $submitButton.data('clickfunction') !== '') {
                    const clickHandler = window[$submitButton.data('clickfunction')]
                    selfModal.options.APIConfirms[i] = (tmpApi) => {
                        let clickResult = clickHandler(selfModal, tmpApi)
                        if (clickResult !== undefined) {
                            return clickResult
                                .then((data) => {
                                    if (data.success) {
                                        selfModal.options.POSTSuccessCallback([data, this])
                                    } else { // Validation error
                                        selfModal.injectFormValidationFeedback(form, data.errors)
                                        return Promise.reject('Validation error');
                                    }
                                })
                                .catch((errorMessage) => {
                                    selfModal.options.POSTFailCallback(errorMessage)
                                    return Promise.reject(errorMessage);
                                })
                        }
                    }
                }
                $submitButton.click(selfModal.getConfirmationHandlerFunction($submitButton, i))
            })
        } else {
            let $submitButton = this.$modal.find('.modal-footer #submitButton')
            if (!$submitButton[0]) {
                $submitButton = this.$modal.find('.modal-footer .modal-confirm-button')
            }
            if ($submitButton[0]) {
                const formID = $submitButton.data('form-id')
                let $form
                if (formID) {
                    $form = $(formID)
                } else {
                    $form = this.$modal.find('form')
                }
                if ($submitButton.data('confirmfunction') !== undefined && $submitButton.data('confirmfunction') !== '') {
                    $submitButton[0].removeAttribute('onclick')
                    const clickHandler = window[$submitButton.data('confirmfunction')]
                    if (clickHandler === undefined) {
                        console.error(`Function \`${$submitButton.data('confirmfunction')}\` is not defined`)
                    }
                    this.options.APIConfirm = (tmpApi) => {
                        let clickResult = clickHandler(this, tmpApi)
                        if (clickResult !== undefined) {
                            return clickResult
                                .then((data) => {
                                    if (!data) {
                                        this.options.POSTSuccessCallback([data, this])
                                    } else {
                                        if (data.success == undefined || data.success) {
                                            this.options.POSTSuccessCallback([data, this])
                                        } else { // Validation error
                                            this.injectFormValidationFeedback(form, data.errors)
                                            return Promise.reject('Validation error');
                                        }
                                    }
                                })
                                .catch((errorMessage) => {
                                    this.options.POSTFailCallback(errorMessage)
                                    return Promise.reject(errorMessage);
                                })
                        }
                    }
                } else {
                    if ($form[0]) {
                        // Submit the form via the AJAXApi
                        $submitButton[0].removeAttribute('onclick')
                        this.options.APIConfirm = (tmpApi) => {
                            return tmpApi.postForm($form[0])
                                .then((data) => {
                                    if (!data) {
                                        this.options.POSTSuccessCallback([data, this])
                                    } else {
                                        if (data.success == undefined || data.success) {
                                            this.options.POSTSuccessCallback([data, this])
                                        } else { // Validation error
                                            this.injectFormValidationFeedback(form, data.errors)
                                            return Promise.reject('Validation error');
                                        }
                                    }
                                })
                                .catch((errorMessage) => {
                                    this.options.POSTFailCallback([errorMessage, this])
                                    return Promise.reject(errorMessage);
                                })
                        }
                    }
                }
                $submitButton.click(this.getConfirmationHandlerFunction($submitButton))
            }
        }
    }
}

/** Class representing a loading overlay */
class OverlayFactory {
    /**
     * Create a loading overlay
     * @param {(jQuery|string|HTMLButtonElement)} node    - The node on which the overlay should be placed
     * @param {Object}                            options - The options supported by OverlayFactory#defaultOptions 
     */
    constructor(node, options={}) {
        this.node = node
        this.$node = $(this.node)
        this.options = Object.assign({}, OverlayFactory.defaultOptions, options)
        this.options.auto = options.auto ? this.options.auto : !(options.variant || options.spinnerVariant)
        if (this.options.auto) {
            this.adjustOptionsBasedOnNode()
        }
    }

    /**
     * @namespace
     * @property {string}  text - A small text indicating the reason of the overlay
     * @property {string=('primary'|'secondary'|'success'|'danger'|'warning'|'info'|'light'|'dark'|'white'|'transparent')} variant - The variant of the overlay
     * @property {number|string}  opacity        - The opacity of the overlay
     * @property {boolean} rounded        - If the overlay should be rounded
     * @property {boolean}  auto           - Whether overlay and spinner options should be adapted automatically based on the node
     * @property {string=('primary'|'secondary'|'success'|'danger'|'warning'|'info'|'light'|'dark'|'white'|'transparent')} spinnerVariant - The variant of the spinner
     * @property {string=('xs', 'sm', 'md')} spinnerSize   -The size of the spinner
     * @property {string=('border'|'grow')} spinnerType   - The type of the spinner defined in Bootstrap
     */
    static defaultOptions = {
        text: '',
        variant: '',
        opacity: '',
        blur: '2px',
        rounded: false,
        auto: true,
        spinnerVariant: '',
        spinnerSize: 'md',
        spinnerType: 'border',
        fallbackBootstrapVariant: '',
        wrapperCSSDisplay: '',
    }

    static overlayWrapper = '<div aria-busy="true" class="position-relative"/>'
    static overlayContainer = '<div class="position-absolute text-nowrap loading-overlay-container" style="inset: 0px; z-index: 1100;"/>'
    static overlayBg = '<div class="position-absolute loading-overlay" style="inset: 0px;"/>'
    static overlaySpinner = '<div class="position-absolute" style="top: 50%; left: 50%; transform: translateX(-50%) translateY(-50%);"><span aria-hidden="true" class=""><!----></span></div></div>'
    static overlayText = '<span class="ml-1 align-text-top"></span>'

    shown = false
    originalNodeIndex = 0

     /** Create the HTML of the overlay */
    buildOverlay() {
        this.$overlayWrapper = $(OverlayFactory.overlayWrapper)
        if (this.options.wrapperCSSDisplay) {
            this.$overlayWrapper.css('display', this.options.wrapperCSSDisplay)
        }
        if (this.$node[0]) {
            const boundingRect = this.$node[0].getBoundingClientRect()
            this.$overlayWrapper.css('min-height', Math.max(boundingRect.height, 20))
            this.$overlayWrapper.css('min-width', Math.max(boundingRect.width, 20))
            if (this.$node.hasClass('row')) {
                this.$overlayWrapper.addClass('row')
            }
        }
        this.$overlayContainer = $(OverlayFactory.overlayContainer)
        this.$overlayBg = $(OverlayFactory.overlayBg)
            .addClass([`bg-${this.options.variant}`, (this.options.rounded ? 'rounded' : '')])
        if (this.options.opacity !== '') {
            this.$overlayBg.css('opacity', this.options.opacity)
        }
        this.$overlaySpinner = $(OverlayFactory.overlaySpinner)
        this.$overlaySpinner.children()
            .addClass(`spinner-${this.options.spinnerType}`)
            .addClass(`spinner-${this.options.spinnerType}-${this.options.spinnerSize}`)
        if (this.options.spinnerVariant.length > 0) {
            this.$overlaySpinner.children().addClass(`text-${this.options.spinnerVariant}`)
        }
        if (this.options.text.length > 0) {
            this.$overlayText = $(OverlayFactory.overlayText);
            this.$overlayText.addClass(`text-${this.options.spinnerVariant}`)
                .text(this.options.text)
            this.$overlaySpinner.append(this.$overlayText)
        }
    }

    /** Create the overlay, attach it to the DOM and display it */
    show() {
        this.buildOverlay()
        this.mountOverlay()
        this.shown = true
    }

    /** Hide the overlay and remove it from the DOM */
    hide() {
        if (this.shown) {
            this.unmountOverlay()
        }
        this.shown = false
    }

    /** Attach the overlay to the DOM */
    mountOverlay() {
        this.originalNodeIndex = this.$node.index()
        this.$overlayBg.appendTo(this.$overlayContainer)
        this.$overlaySpinner.appendTo(this.$overlayContainer)
        this.appendToIndex(this.$overlayWrapper, this.$node.parent(), this.originalNodeIndex)
        this.$overlayContainer.appendTo(this.$overlayWrapper)
        this.$node.prependTo(this.$overlayWrapper)
    }

    /** Remove the overlay from the DOM */
    unmountOverlay() {
        this.appendToIndex(this.$node, this.$overlayWrapper.parent(), this.originalNodeIndex)
        this.$overlayWrapper.remove()
        this.originalNodeIndex = 0
    }

    /** Append a node to the provided DOM index */
    appendToIndex($node, $targetContainer, index) {
        const $target = $targetContainer.children().eq(index);
        $node.insertBefore($target);
    }

    /** Adjust instance's options based on the provided node */
    adjustOptionsBasedOnNode() {
        if (this.$node.width() < 50 || this.$node.height() < 50) {
            this.options.spinnerSmall = true
        }
        if (this.$node.is('input[type="checkbox"]') || this.$node.css('border-radius') !== '0px') {
            this.options.rounded = true
        }
        this.options.wrapperCSSDisplay = this.$node.css('display')
        let classes = this.$node.attr('class')
        if (classes !== undefined) {
            classes = classes.split(' ')
            const detectedVariant = OverlayFactory.detectedBootstrapVariant(classes, this.options.fallbackBootstrapVariant)
            this.options.spinnerVariant = detectedVariant
        }
    }

    /**
     * Detect the bootstrap variant from a list of classes
     * @param {Array} classes - A list of classes containg a bootstrap variant 
     */
    static detectedBootstrapVariant(classes, fallback = OverlayFactory.defaultOptions.fallbackBootstrapVariant) {
        const re = /^[a-zA-Z]+-(?<variant>primary|success|danger|warning|info|light|dark|white|transparent)$/;
        let result
        for (let i=0; i<classes.length; i++) {
            let theClass = classes[i]
            if ((result = re.exec(theClass)) !== null) {
                if (result.groups !== undefined && result.groups.variant !== undefined) {
                    return result.groups.variant
                }
            }
        }
        return fallback
    }
}

/** Class representing a FormValidationHelper */
class FormValidationHelper {
    /**
     * Create a FormValidationHelper.
     * @param  {Object} options - The options supported by FormValidationHelper#defaultOptions
     */
    constructor(form, options={}) {
        this.form = form
        this.options = Object.assign({}, Toaster.defaultOptions, options)
    }

    /**
     * @namespace
     */
    static defaultOptions = {
    }

    /**
     * Create node containing validation information from validationError. If no field can be associated to the error, it will be placed on top
     * @param  {Object} validationErrors - The validation errors to be displayed. Keys are the fieldName that had errors, values are the error text
     */
    injectValidationErrors(validationErrors) {
        this.cleanValidationErrors()
        for (const [fieldName, errors] of Object.entries(validationErrors)) {
            this.injectValidationErrorInForm(fieldName, errors)
        }
    }

    injectValidationErrorInForm(fieldName, errors) {
        const inputField = Array.from(this.form).find(node => { return node.name == fieldName })
        if (inputField !== undefined) {
            const $messageNode = this.buildValidationMessageNode(fieldName, errors)
            const $inputField = $(inputField)
            $inputField.addClass('is-invalid')
            $messageNode.insertAfter($inputField)
        } else {
            const $messageNode = this.buildValidationMessageNode(fieldName, errors, true)
            const $flashContainer = $(this.form).parent().find('#flashContainer')
            $messageNode.insertAfter($flashContainer)
        }
    }

    buildValidationMessageNode(fieldName, errors, isAlert=false) {
        const $messageNode = $('<div></div>')
        if (isAlert) {
            $messageNode.addClass('alert alert-danger').attr('role', 'alert')
            $messageNode.append($('<strong></strong>').text(`${fieldName}: `))
        } else {
            $messageNode.addClass('invalid-feedback')
        }
        if (typeof errors === 'object') {
            const hasMultipleErrors = Object.keys(errors).length > 1
            for (const [ruleName, error] of Object.entries(errors)) {
                if (hasMultipleErrors) {
                    $messageNode.append($('<li></li>').text(error))
                } else {
                    $messageNode.append($('<span></span>').text(error))
                }
            }
        } else {
            $messageNode.text(errors)
        }
        return $messageNode
    }

    cleanValidationErrors() {
        $(this.form).find('textarea, input, select').removeClass('is-invalid')
        $(this.form).find('.invalid-feedback').remove()
        $(this.form).parent().find('.alert').remove()
    }

}

/** Class representing a Popover */
class PopoverFactory {
    /**
     * Create a Popover.
     * @param  {Object} element - The target element on which to attach the popover
     * @param  {Object} options - The options supported by PopoverFactory#defaultOptions
     */
    constructor(element, options) {
        this.element = $(element)[0]
        this.options = Object.assign({}, PopoverFactory.defaultOptions, options)
    }

    /**
     * @namespace
     * @property {string} title                            - The title's content of the popover
     * @property {string} titleHtml                        - The raw HTML title's content of the popover
     * @property {string} body                             - The body's content of the popover
     * @property {string} bodyHtml                         - The raw HTML body's content of the popover
     * @property {string} content                          - Forward the popover's content to the bootstrap popover constructor
     * @property {string} html                             - Manually allow HTML in both the title and body
     * @property {string=('primary'|'secondary'|'success'|'danger'|'warning'|'info'|'light'|'dark'|'white'|'transparent')} variant - The variant of the popover
     * @property {string} popoverClass                       - Classes to be added to the popover's container
     * @property {string} container                        - Appends the popover to a specific element
     * @property {string=('auto'|'top'|'bottom'|'left'|'right')} placement                        - How to position the popover
     */
    static defaultOptions = {
        title: '',
        titleHtml: false,
        body: false,
        bodyHtml: false,
        content: null,
        html: false,
        popoverClass: '',
        container: false,
        placement: 'right',
    }

    /** Create the HTML of the modal and inject it into the DOM */
    makePopover() {
        if (this.isValid()) {
            if (this.options.titleHtml || this.options.bodyHtml) {
                this.options.html = true
            }
            this.options.title = this.options.titleHtml ? this.options.titleHtml : sanitize(this.options.title)
            if (this.options.content === null) {
                this.options.content = this.options.bodyHtml ? this.options.bodyHtml : sanitize(this.options.body)
            }
            this.popoverInstance = new bootstrap.Popover(this.element, this.options)
        } else {
            console.error('Popover not valid')
        }
    }

    /** Display the popover */
    show() {
        this.popoverInstance.show()
    }

    /** Hide the popover */
    hide() {
        this.popoverInstance.hide()
    }

    /** Updates the position of an element’s popover. */
    updatePosition() {
        this.popoverInstance.update()
    }

    /** Hides and destroys an element’s popover */
    dispose() {
        this.popoverInstance.dispose();
    }

    /**
     * Check wheter a popover is valid
     * @return {boolean} Return true if the popover contains at least data to be rendered
     */
    isValid() {
        return this.options.title !== false || this.options.titleHtml !== false ||
            this.options.body !== false || this.options.bodyHtml !== false ||
            this.options.rawHtml !== false
    }
}

class HtmlHelper {
    static table(head=[], body=[], options={}) {
        const $table = $('<table/>')
        const $thead = $('<thead/>')
        const $tbody = $('<tbody/>')
        
        $table.addClass('table')
        if (options.striped) {
            $table.addClass('table-striped')
        }
        if (options.bordered) {
            $table.addClass('table-bordered')
        }
        if (options.borderless) {
            $table.addClass('table-borderless')
        }
        if (options.hoverable) {
            $table.addClass('table-hover')
        }
        if (options.small) {
            $table.addClass('table-sm')
        }
        if (options.variant) {
            $table.addClass(`table-${options.variant}`)
        }
        if (options.fixed_layout) {
            $table.css('table-layout', 'fixed')
        }
        if (options.tableClass) {
            $table.addClass(options.tableClass)
        }

        let $caption = null
        if (options.caption) {
            $caption = $('<caption/>')
            if (options.caption instanceof jQuery) {
                $caption = options.caption
            } else {
                $caption.text(options.caption)
            }
        }

        let $theadRow = null
        if (head) {
            $theadRow = $('<tr/>')
            head.forEach(head => {
                if (head instanceof jQuery) {
                    $theadRow.append($('<td/>').append(head))
                } else {
                    $theadRow.append($('<th/>').text(head))
                }
            })
            $thead.append($theadRow)
        }

        body.forEach(row => {
            const $bodyRow = $('<tr/>')
            row.forEach(item => {
                if (item instanceof jQuery) {
                    if (item.is('td')) {
                        $bodyRow.append(item)
                    } else {
                        $bodyRow.append($('<td/>').append(item))
                    }
                } else {
                    $bodyRow.append($('<td/>').text(item))
                }
            })
            $tbody.append($bodyRow)
        })

        $table.append($caption, $thead, $tbody)
        if (options.responsive) {
            options.responsiveBreakpoint = options.responsiveBreakpoint !== undefined ? options.responsiveBreakpoint : ''
            $table = $('<div/>').addClass(options.responsiveBreakpoint !== undefined ? `table-responsive-${options.responsiveBreakpoint}` : 'table-responsive').append($table)
        }
        return $table
    }

}
