/** AJAXApi class providing helpers to perform AJAX request */
class AJAXApi {
    static genericRequestHeaders = {
        'X-Requested-With': 'XMLHttpRequest'
    };
    static genericRequestConfigGET = {
        headers: new Headers(Object.assign({}, AJAXApi.genericRequestHeaders))
    }
    static genericRequestConfigPOST = {
        headers: new Headers(Object.assign({}, AJAXApi.genericRequestHeaders)),
        redirect: 'manual',
        method: 'POST',
    }
    static genericRequestConfigGETJSON = {
        headers: new Headers(Object.assign({}, AJAXApi.genericRequestHeaders, {Accept: 'application/json'}))
    }

    /**
     * @namespace
     * @property {boolean}         provideFeedback         - Should a toast be used to provide feedback upon request fulfillment
     * @property {(jQuery|string)} statusNode              - The node on which the loading overlay should be placed (OverlayFactory.node)
     * @property {Object}          statusNodeOverlayConfig - The configuration (OverlayFactory.options) of the overlay applied on the status node
     * @property {Object}          errorToastOptions       - The options supported by Toaster#defaultOptions
     * @property {Object}          successToastOptions     - The options supported by Toaster#defaultOptions
     */
    static defaultOptions = {
        provideFeedback: true,
        statusNode: false,
        statusNodeOverlayConfig: {},
        errorToastOptions: {
            delay: 10000
        },
        successToastOptions: {
        },
    }
    options = {}
    loadingOverlay = false

    /**
     * Instantiate an AJAXApi object.
     * @param  {Object} options - The options supported by AJAXApi#defaultOptions
     */
    constructor(options) {
        this.mergeOptions(AJAXApi.defaultOptions)
        this.mergeOptions(options)
    }

    /**
     * Based on the current configuration, provide feedback to the user via toast, console or do not
     * @param {Object} toastOptions - The options supported by Toaster#defaultOptions
     * @param {boolean} isError     - If true and toast feedback is disable, write the feedback in the console
     * @param {boolean} skip        - If true, skip the feedback regardless of the configuration
     */
    provideFeedback(toastOptions, isError=false, skip=false) {
        const alteredToastOptions = Object.assign(
            {},
            isError ? AJAXApi.defaultOptions.errorToastOptions : AJAXApi.defaultOptions.successToastOptions,
            toastOptions
        )
        if (!skip) {
            if (this.options.provideFeedback) {
                UI.toast(alteredToastOptions)
            } else {
                if (isError) {
                    console.error(alteredToastOptions.body)
                }
            }
        }
    }

    provideSuccessFeedback(response, toastOptions, skip=false) {
        let alteredToastOptions = Object.assign(
            {
                'variant': 'success'
            },
            AJAXApi.defaultOptions.successToastOptions,
            toastOptions
        )
        alteredToastOptions.body = response.message
        if (!skip && this.options.provideFeedback) {
            UI.toast(alteredToastOptions)
        }
    }

    provideFailureFeedback(response, toastOptions, skip=false) {
        let alteredToastOptions = Object.assign(
            {
                'variant': 'danger'
            },
            AJAXApi.defaultOptions.errorToastOptions,
            toastOptions
        )
        if (response.message && response.errors) {
            if (Array.isArray(response.errors)) {
                alteredToastOptions.title = response.message
                alteredToastOptions.body = response.errors.join(', ')
            } else if (typeof response.errors === 'string') {
                alteredToastOptions.title = response.message
                alteredToastOptions.body = response.errors
            } else {
                alteredToastOptions.title = 'There has been a problem with the operation'
                alteredToastOptions.body = response.message
            }
        } else {
            alteredToastOptions.title = 'There has been a problem with the operation'
            alteredToastOptions.body = response.message
        }
        if (!skip && this.options.provideFeedback) {
            UI.toast(alteredToastOptions)
            console.warn(alteredToastOptions.body)
        }
    }

    /**
     * Merge newOptions configuration into the current object
     * @param {Object} The options supported by AJAXApi#defaultOptions
     */
    mergeOptions(newOptions) {
        this.options = Object.assign({}, this.options, newOptions)
    }

    /**
     *
     * @param  {FormData} formData       - The data of a form
     * @param  {Object}   dataToMerge    - Data to be merge into formData
     * @return {FormData} The form data merged with the additional dataToMerge data
     */
    static mergeFormData(formData, dataToMerge) {
        for (const [fieldName, value] of Object.entries(dataToMerge)) {
            formData.set(fieldName, value)
        }
        return formData
    }

    /**
     * @param {string} url           - The URL to fetch
     * @param {Object} [options={}]  - The options supported by AJAXApi#defaultOptions
     * @return {Promise<string>} Promise object resolving to the fetched HTML
     */
    static async quickFetchURL(url, options={}) {
        const constAlteredOptions = Object.assign({}, {provideFeedback: false}, options)
        const tmpApi = new AJAXApi(constAlteredOptions)
        return tmpApi.fetchURL(url, constAlteredOptions.skipRequestHooks)
    }

    /**
     * @param {string} url           - The URL to fetch
     * @param {Object} [options={}]  - The options supported by AJAXApi#defaultOptions
     * @return {Promise<Object>} Promise object resolving to the fetched HTML
     */
    static async quickFetchJSON(url, options={}) {
        const constAlteredOptions = Object.assign({}, {provideFeedback: false}, options)
        const tmpApi = new AJAXApi(constAlteredOptions)
        return tmpApi.fetchJSON(url, constAlteredOptions.skipRequestHooks)
    }

    /**
     * @param {string} url          - The URL to fetch
     * @param {Object} [options={}] - The options supported by AJAXApi#defaultOptions
     * @return {Promise<HTMLFormElement>} Promise object resolving to the fetched form
     */
    static async quickFetchForm(url, options={}) {
        const constAlteredOptions = Object.assign({}, {provideFeedback: false}, options)
        const tmpApi = new AJAXApi(constAlteredOptions)
        return tmpApi.fetchForm(url, constAlteredOptions.skipRequestHooks)
    }

    /**
     * @param {HTMLFormElement} form    - The form to be posted
     * @param {Object} [dataToMerge={}] - Additional data to be integrated or modified in the form
     * @param {Object} [options={}]     - The options supported by AJAXApi#defaultOptions
     * @return {Promise<Object>} Promise object resolving to the result of the POST operation
     */
    static async quickPostForm(form, dataToMerge={}, options={}) {
        const constAlteredOptions = Object.assign({}, {}, options)
        const tmpApi = new AJAXApi(constAlteredOptions)
        return tmpApi.postForm(form, dataToMerge, constAlteredOptions.skipRequestHooks)
    }

    /**
     * @param {string} url              - The URL to on which to execute the POST
     * @param {Object} [data={}]        - The data to be posted
     * @param {Object} [options={}]     - The options supported by AJAXApi#defaultOptions 
     * @return {Promise<Object>} Promise object resolving to the result of the POST operation
     */
    static async quickPostData(url, data={}, options={}) {
        const constAlteredOptions = Object.assign({}, {}, options)
        const tmpApi = new AJAXApi(constAlteredOptions)
        return tmpApi.postData(url, data, constAlteredOptions.skipRequestHooks)
    }

    /**
     * @param {string} url              - The URL from which to fetch the form
     * @param {Object} [dataToMerge={}] - Additional data to be integrated or modified in the form
     * @param {Object} [options={}]     - The options supported by AJAXApi#defaultOptions 
     * @return {Promise<Object>} Promise object resolving to the result of the POST operation
     */
    static async quickFetchAndPostForm(url, dataToMerge={}, options={}) {
        const constAlteredOptions = Object.assign({}, {}, options)
        const tmpApi = new AJAXApi(constAlteredOptions)
        return tmpApi.fetchAndPostForm(url, dataToMerge, constAlteredOptions.skipRequestHooks, constAlteredOptions.skipFeedback)
    }

    /**
     * @param {string}  url                      - The URL to fetch
     * @param {boolean} [skipRequestHooks=false] - If true, default request hooks will be skipped
     * @param {boolean} [skipFeedback=false]     - Pass this value to the AJAXApi.provideFeedback function
     * @return {Promise<string>} Promise object resolving to the fetched HTML
     */
    async fetchURL(url, skipRequestHooks=false, skipFeedback=false) {
        if (!skipRequestHooks) {
            this.beforeRequest()
        }
        let toReturn
        try {
            const response = await fetch(url, AJAXApi.genericRequestConfigGET);
            if (!response.ok) {
                throw new Error(`Network response was not ok. \`${response.statusText}\``)
            }
            const dataHtml = await response.text();
            this.provideSuccessFeedback({message: 'URL fetched'}, {}, skipFeedback)
            toReturn = dataHtml;
        } catch (error) {
            this.provideFailureFeedback(error, {}, skipFeedback)
            toReturn = Promise.reject(error);
        } finally {
            if (!skipRequestHooks) {
                this.afterRequest()
            }
        }
        return toReturn
    }

    /**
     * @param {string}  url                      - The URL to fetch
     * @param {boolean} [skipRequestHooks=false] - If true, default request hooks will be skipped
     * @param {boolean} [skipFeedback=false]     - Pass this value to the AJAXApi.provideFeedback function
     * @return {Promise<string>} Promise object resolving to the fetched JSON
     */
    async fetchJSON(url, skipRequestHooks=false, skipFeedback=false) {
        if (!skipRequestHooks) {
            this.beforeRequest()
        }
        let toReturn
        try {
            const response = await fetch(url, AJAXApi.genericRequestConfigGETJSON);
            if (!response.ok) {
                throw new Error(`Network response was not ok. \`${response.statusText}\``)
            }
            const dataJson = await response.json();
            this.provideSuccessFeedback({message: 'JSON fetched'}, {}, skipFeedback)
            toReturn = dataJson;
        } catch (error) {
            this.provideFailureFeedback(error, {}, skipFeedback)
            toReturn = Promise.reject(error);
        } finally {
            if (!skipRequestHooks) {
                this.afterRequest()
            }
        }
        return toReturn
    }

    /**
     * @param {string}  url                      - The URL to fetch
     * @param {boolean} [skipRequestHooks=false] - If true, default request hooks will be skipped
     * @param {boolean} [skipFeedback=false]     - Pass this value to the AJAXApi.provideFeedback function
     * @return {Promise<HTMLFormElement>} Promise object resolving to the fetched HTML
     */
    async fetchForm(url, skipRequestHooks=false, skipFeedback=false) {
        if (!skipRequestHooks) {
            this.beforeRequest()
        }
        let toReturn
        try {
            const response = await fetch(url, AJAXApi.genericRequestConfigGET);
            if (!response.ok) {
                throw new Error(`Network response was not ok. \`${response.statusText}\``)
            }
            const formHtml = await response.text();
            let tmpNode = document.createElement("div");
            tmpNode.innerHTML = formHtml;
            let form = tmpNode.getElementsByTagName('form');
            if (form.length == 0) {
                throw new Error('The server did not return a form element')
            }
            toReturn = form[0];
        } catch (error) {
            this.provideFailureFeedback(error, {}, skipFeedback)
            toReturn = Promise.reject(error);
        } finally {
            if (!skipRequestHooks) {
                this.afterRequest()
            }
        }
        return toReturn
    }

    /**
     * @param {string}  url                      - The URL to fetch
     * @param {Object}  dataToPost               - data to be posted
     * @param {boolean} [skipRequestHooks=false] - If true, default request hooks will be skipped
     * @param {boolean} [skipFeedback=false]     - Pass this value to the AJAXApi.provideFeedback function
     * @return {Promise<string>} Promise object resolving to the result of the POST
     */
    async postData(url, dataToPost, skipRequestHooks=false, skipFeedback=false) {
        if (!skipRequestHooks) {
            this.beforeRequest()
        }
        let toReturn
        try {
            let formData = new FormData()
            formData = AJAXApi.mergeFormData(formData, dataToPost)
            let requestConfig = AJAXApi.genericRequestConfigPOST
            requestConfig.headers.append('AUTHORIZATION', '~HACKY-HACK~')
            let options = {
                ...requestConfig,
                body: formData,
            };
            const response = await fetch(url, options);
            if (!response.ok) {
                throw new Error(`Network response was not ok. \`${response.statusText}\``)
            }
            const data = await response.json()
            if (data.success) {
                this.provideFeedback({
                    variant: 'success',
                    body: data.message
                }, false, skipFeedback);
                this.provideSuccessFeedback(data, {}, skipFeedback)
                toReturn = data;
            } else {
                this.provideFailureFeedback(data, {}, skipFeedback)
                toReturn = Promise.reject(data.errors);
            }
        } catch (error) {
            this.provideFeedback({
                variant: 'danger',
                title: 'There has been a problem with the operation',
                body: error.message
            }, true, skipFeedback);
            toReturn = Promise.reject(error);
        } finally {
            if (!skipRequestHooks) {
                this.afterRequest()
            }
        }
        return toReturn
    }

     /**
     * @param {HTMLFormElement}  form            - The form to be posted
     * @param {Object} [dataToMerge={}]          - Additional data to be integrated or modified in the form
     * @param {boolean} [skipRequestHooks=false] - If true, default request hooks will be skipped
     * @param {boolean} [skipFeedback=false]     - Pass this value to the AJAXApi.provideFeedback function
     * @return {Promise<Object>} Promise object resolving to the result of the POST operation
     */
    async postForm(form, dataToMerge={}, skipRequestHooks=false, skipFeedback=false) {
        if (!skipRequestHooks) {
            this.beforeRequest()
        }
        let toReturn
        let feedbackShown = false
        try {
            try {
                let formData = new FormData(form)
                formData = AJAXApi.mergeFormData(formData, dataToMerge)
                let requestConfig = AJAXApi.genericRequestConfigPOST
                let options = {
                    ...requestConfig,
                    body: formData,
                };
                const response = await fetch(form.action, options);
                if (!response.ok) {
                    throw new Error(`Network response was not ok. \`${response.statusText}\``)
                }
                const clonedResponse = response.clone()
                try {
                    const data = await response.json()
                    if (data.success) {
                        this.provideSuccessFeedback(data, {}, skipFeedback)
                        toReturn = data;
                    } else {
                        this.provideFailureFeedback(data, {}, skipFeedback)
                        feedbackShown = true
                        this.injectFormValidationFeedback(form, data.errors)
                        toReturn = Promise.reject(data.errors);
                    }
                } catch (error) {
                    this.provideFeedback({
                        variant: 'danger',
                        title: 'There has been a problem with the operation',
                        body: error.message
                    }, true, feedbackShown);
                    toReturn = Promise.reject(error);
                }
            } catch (error) {
                this.provideFeedback({
                    variant: 'danger',
                    title: 'There has been a problem with the operation',
                    body: error.message
                }, true, feedbackShown);
                toReturn = Promise.reject(error);
            }
        } catch (error) {
            toReturn = Promise.reject(error);
        } finally {
            if (!skipRequestHooks) {
                this.afterRequest()
            }
        }
        return toReturn
    }

    /**
     * @param {string} url                       - The URL from which to fetch the form
     * @param {Object} [dataToMerge={}]          - Additional data to be integrated or modified in the form
     * @param {boolean} [skipRequestHooks=false] - If true, default request hooks will be skipped
     * @return {Promise<Object>} Promise object resolving to the result of the POST operation
     */
    async fetchAndPostForm(url, dataToMerge={}, skipRequestHooks=false, skipFeedback=false) {
        if (!skipRequestHooks) {
            this.beforeRequest()
        }
        let toReturn
        try {
            const form = await this.fetchForm(url, true, true);
            toReturn = await this.postForm(form, dataToMerge, true, skipFeedback)
        } catch (error) {
            toReturn = Promise.reject(error);
        } finally {
            if (!skipRequestHooks) {
                this.afterRequest()
            }
        }
        return toReturn
    }

    /**
     * @param {HTMLFormElement} form - The form form which the POST operation is coming from
     * @param {Object} [validationErrors={}]   - Validation errors reported by the server
     */
    injectFormValidationFeedback(form, validationErrors) {
        const formHelper = new FormValidationHelper(form)
        formHelper.injectValidationErrors(validationErrors)
    }

    /** Based on the configuration, show the loading overlay */
    beforeRequest() {
        if (this.options.statusNode !== false) {
            this.toggleLoading(true)
        }
    }

    /** Based on the configuration, hide the loading overlay */
    afterRequest() {
        if (this.options.statusNode !== false) {
            this.toggleLoading(false)
        }
    }

    /** Show or hide the loading overlay */
    toggleLoading(loading) {
        if (this.loadingOverlay === false) {
            this.loadingOverlay = new OverlayFactory(this.options.statusNode, this.options.statusNodeOverlayConfig);
        }
        if (loading) {
            this.loadingOverlay.show()
        } else {
            this.loadingOverlay.hide()

        }
    }
}
