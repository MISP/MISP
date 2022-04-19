/*! jQuery UI - v1.13.1 - 2022-04-17
* http://jqueryui.com
* Includes: effect.js, effects/effect-slide.js
* Copyright jQuery Foundation and other contributors; Licensed MIT */

( function( factory ) {
    "use strict";

    if ( typeof define === "function" && define.amd ) {

        // AMD. Register as an anonymous module.
        define( [ "jquery" ], factory );
    } else {

        // Browser globals
        factory( jQuery );
    }
} )( function( $ ) {
    "use strict";

    $.ui = $.ui || {};

    var version = $.ui.version = "1.13.1";



// Create a local jQuery because jQuery Color relies on it and the
// global may not exist with AMD and a custom build (#10199).
// This module is a noop if used as a regular AMD module.
// eslint-disable-next-line no-unused-vars
    var jQuery = $;


    /*!
     * jQuery Color Animations v2.2.0
     * https://github.com/jquery/jquery-color
     *
     * Copyright OpenJS Foundation and other contributors
     * Released under the MIT license.
     * http://jquery.org/license
     *
     * Date: Sun May 10 09:02:36 2020 +0200
     */



    var stepHooks = "backgroundColor borderBottomColor borderLeftColor borderRightColor " +
            "borderTopColor color columnRuleColor outlineColor textDecorationColor textEmphasisColor",

        class2type = {},
        toString = class2type.toString,

        // plusequals test for += 100 -= 100
        rplusequals = /^([\-+])=\s*(\d+\.?\d*)/,

        // a set of RE's that can match strings and generate color tuples.
        stringParsers = [ {
            re: /rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
            parse: function( execResult ) {
                return [
                    execResult[ 1 ],
                    execResult[ 2 ],
                    execResult[ 3 ],
                    execResult[ 4 ]
                ];
            }
        }, {
            re: /rgba?\(\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
            parse: function( execResult ) {
                return [
                    execResult[ 1 ] * 2.55,
                    execResult[ 2 ] * 2.55,
                    execResult[ 3 ] * 2.55,
                    execResult[ 4 ]
                ];
            }
        }, {

            // this regex ignores A-F because it's compared against an already lowercased string
            re: /#([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})?/,
            parse: function( execResult ) {
                return [
                    parseInt( execResult[ 1 ], 16 ),
                    parseInt( execResult[ 2 ], 16 ),
                    parseInt( execResult[ 3 ], 16 ),
                    execResult[ 4 ] ?
                        ( parseInt( execResult[ 4 ], 16 ) / 255 ).toFixed( 2 ) :
                        1
                ];
            }
        }, {

            // this regex ignores A-F because it's compared against an already lowercased string
            re: /#([a-f0-9])([a-f0-9])([a-f0-9])([a-f0-9])?/,
            parse: function( execResult ) {
                return [
                    parseInt( execResult[ 1 ] + execResult[ 1 ], 16 ),
                    parseInt( execResult[ 2 ] + execResult[ 2 ], 16 ),
                    parseInt( execResult[ 3 ] + execResult[ 3 ], 16 ),
                    execResult[ 4 ] ?
                        ( parseInt( execResult[ 4 ] + execResult[ 4 ], 16 ) / 255 )
                            .toFixed( 2 ) :
                        1
                ];
            }
        }, {
            re: /hsla?\(\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
            space: "hsla",
            parse: function( execResult ) {
                return [
                    execResult[ 1 ],
                    execResult[ 2 ] / 100,
                    execResult[ 3 ] / 100,
                    execResult[ 4 ]
                ];
            }
        } ],

        // jQuery.Color( )
        color = jQuery.Color = function( color, green, blue, alpha ) {
            return new jQuery.Color.fn.parse( color, green, blue, alpha );
        },
        spaces = {
            rgba: {
                props: {
                    red: {
                        idx: 0,
                        type: "byte"
                    },
                    green: {
                        idx: 1,
                        type: "byte"
                    },
                    blue: {
                        idx: 2,
                        type: "byte"
                    }
                }
            },

            hsla: {
                props: {
                    hue: {
                        idx: 0,
                        type: "degrees"
                    },
                    saturation: {
                        idx: 1,
                        type: "percent"
                    },
                    lightness: {
                        idx: 2,
                        type: "percent"
                    }
                }
            }
        },
        propTypes = {
            "byte": {
                floor: true,
                max: 255
            },
            "percent": {
                max: 1
            },
            "degrees": {
                mod: 360,
                floor: true
            }
        },
        support = color.support = {},

        // element for support tests
        supportElem = jQuery( "<p>" )[ 0 ],

        // colors = jQuery.Color.names
        colors,

        // local aliases of functions called often
        each = jQuery.each;

// determine rgba support immediately
    supportElem.style.cssText = "background-color:rgba(1,1,1,.5)";
    support.rgba = supportElem.style.backgroundColor.indexOf( "rgba" ) > -1;

// define cache name and alpha properties
// for rgba and hsla spaces
    each( spaces, function( spaceName, space ) {
        space.cache = "_" + spaceName;
        space.props.alpha = {
            idx: 3,
            type: "percent",
            def: 1
        };
    } );

// Populate the class2type map
    jQuery.each( "Boolean Number String Function Array Date RegExp Object Error Symbol".split( " " ),
        function( _i, name ) {
            class2type[ "[object " + name + "]" ] = name.toLowerCase();
        } );

    function getType( obj ) {
        if ( obj == null ) {
            return obj + "";
        }

        return typeof obj === "object" ?
            class2type[ toString.call( obj ) ] || "object" :
            typeof obj;
    }

    function clamp( value, prop, allowEmpty ) {
        var type = propTypes[ prop.type ] || {};

        if ( value == null ) {
            return ( allowEmpty || !prop.def ) ? null : prop.def;
        }

        // ~~ is an short way of doing floor for positive numbers
        value = type.floor ? ~~value : parseFloat( value );

        // IE will pass in empty strings as value for alpha,
        // which will hit this case
        if ( isNaN( value ) ) {
            return prop.def;
        }

        if ( type.mod ) {

            // we add mod before modding to make sure that negatives values
            // get converted properly: -10 -> 350
            return ( value + type.mod ) % type.mod;
        }

        // for now all property types without mod have min and max
        return Math.min( type.max, Math.max( 0, value ) );
    }

    function stringParse( string ) {
        var inst = color(),
            rgba = inst._rgba = [];

        string = string.toLowerCase();

        each( stringParsers, function( _i, parser ) {
            var parsed,
                match = parser.re.exec( string ),
                values = match && parser.parse( match ),
                spaceName = parser.space || "rgba";

            if ( values ) {
                parsed = inst[ spaceName ]( values );

                // if this was an rgba parse the assignment might happen twice
                // oh well....
                inst[ spaces[ spaceName ].cache ] = parsed[ spaces[ spaceName ].cache ];
                rgba = inst._rgba = parsed._rgba;

                // exit each( stringParsers ) here because we matched
                return false;
            }
        } );

        // Found a stringParser that handled it
        if ( rgba.length ) {

            // if this came from a parsed string, force "transparent" when alpha is 0
            // chrome, (and maybe others) return "transparent" as rgba(0,0,0,0)
            if ( rgba.join() === "0,0,0,0" ) {
                jQuery.extend( rgba, colors.transparent );
            }
            return inst;
        }

        // named colors
        return colors[ string ];
    }

    color.fn = jQuery.extend( color.prototype, {
        parse: function( red, green, blue, alpha ) {
            if ( red === undefined ) {
                this._rgba = [ null, null, null, null ];
                return this;
            }
            if ( red.jquery || red.nodeType ) {
                red = jQuery( red ).css( green );
                green = undefined;
            }

            var inst = this,
                type = getType( red ),
                rgba = this._rgba = [];

            // more than 1 argument specified - assume ( red, green, blue, alpha )
            if ( green !== undefined ) {
                red = [ red, green, blue, alpha ];
                type = "array";
            }

            if ( type === "string" ) {
                return this.parse( stringParse( red ) || colors._default );
            }

            if ( type === "array" ) {
                each( spaces.rgba.props, function( _key, prop ) {
                    rgba[ prop.idx ] = clamp( red[ prop.idx ], prop );
                } );
                return this;
            }

            if ( type === "object" ) {
                if ( red instanceof color ) {
                    each( spaces, function( _spaceName, space ) {
                        if ( red[ space.cache ] ) {
                            inst[ space.cache ] = red[ space.cache ].slice();
                        }
                    } );
                } else {
                    each( spaces, function( _spaceName, space ) {
                        var cache = space.cache;
                        each( space.props, function( key, prop ) {

                            // if the cache doesn't exist, and we know how to convert
                            if ( !inst[ cache ] && space.to ) {

                                // if the value was null, we don't need to copy it
                                // if the key was alpha, we don't need to copy it either
                                if ( key === "alpha" || red[ key ] == null ) {
                                    return;
                                }
                                inst[ cache ] = space.to( inst._rgba );
                            }

                            // this is the only case where we allow nulls for ALL properties.
                            // call clamp with alwaysAllowEmpty
                            inst[ cache ][ prop.idx ] = clamp( red[ key ], prop, true );
                        } );

                        // everything defined but alpha?
                        if ( inst[ cache ] && jQuery.inArray( null, inst[ cache ].slice( 0, 3 ) ) < 0 ) {

                            // use the default of 1
                            if ( inst[ cache ][ 3 ] == null ) {
                                inst[ cache ][ 3 ] = 1;
                            }

                            if ( space.from ) {
                                inst._rgba = space.from( inst[ cache ] );
                            }
                        }
                    } );
                }
                return this;
            }
        },
        is: function( compare ) {
            var is = color( compare ),
                same = true,
                inst = this;

            each( spaces, function( _, space ) {
                var localCache,
                    isCache = is[ space.cache ];
                if ( isCache ) {
                    localCache = inst[ space.cache ] || space.to && space.to( inst._rgba ) || [];
                    each( space.props, function( _, prop ) {
                        if ( isCache[ prop.idx ] != null ) {
                            same = ( isCache[ prop.idx ] === localCache[ prop.idx ] );
                            return same;
                        }
                    } );
                }
                return same;
            } );
            return same;
        },
        _space: function() {
            var used = [],
                inst = this;
            each( spaces, function( spaceName, space ) {
                if ( inst[ space.cache ] ) {
                    used.push( spaceName );
                }
            } );
            return used.pop();
        },
        transition: function( other, distance ) {
            var end = color( other ),
                spaceName = end._space(),
                space = spaces[ spaceName ],
                startColor = this.alpha() === 0 ? color( "transparent" ) : this,
                start = startColor[ space.cache ] || space.to( startColor._rgba ),
                result = start.slice();

            end = end[ space.cache ];
            each( space.props, function( _key, prop ) {
                var index = prop.idx,
                    startValue = start[ index ],
                    endValue = end[ index ],
                    type = propTypes[ prop.type ] || {};

                // if null, don't override start value
                if ( endValue === null ) {
                    return;
                }

                // if null - use end
                if ( startValue === null ) {
                    result[ index ] = endValue;
                } else {
                    if ( type.mod ) {
                        if ( endValue - startValue > type.mod / 2 ) {
                            startValue += type.mod;
                        } else if ( startValue - endValue > type.mod / 2 ) {
                            startValue -= type.mod;
                        }
                    }
                    result[ index ] = clamp( ( endValue - startValue ) * distance + startValue, prop );
                }
            } );
            return this[ spaceName ]( result );
        },
        blend: function( opaque ) {

            // if we are already opaque - return ourself
            if ( this._rgba[ 3 ] === 1 ) {
                return this;
            }

            var rgb = this._rgba.slice(),
                a = rgb.pop(),
                blend = color( opaque )._rgba;

            return color( jQuery.map( rgb, function( v, i ) {
                return ( 1 - a ) * blend[ i ] + a * v;
            } ) );
        },
        toRgbaString: function() {
            var prefix = "rgba(",
                rgba = jQuery.map( this._rgba, function( v, i ) {
                    if ( v != null ) {
                        return v;
                    }
                    return i > 2 ? 1 : 0;
                } );

            if ( rgba[ 3 ] === 1 ) {
                rgba.pop();
                prefix = "rgb(";
            }

            return prefix + rgba.join() + ")";
        },
        toHslaString: function() {
            var prefix = "hsla(",
                hsla = jQuery.map( this.hsla(), function( v, i ) {
                    if ( v == null ) {
                        v = i > 2 ? 1 : 0;
                    }

                    // catch 1 and 2
                    if ( i && i < 3 ) {
                        v = Math.round( v * 100 ) + "%";
                    }
                    return v;
                } );

            if ( hsla[ 3 ] === 1 ) {
                hsla.pop();
                prefix = "hsl(";
            }
            return prefix + hsla.join() + ")";
        },
        toHexString: function( includeAlpha ) {
            var rgba = this._rgba.slice(),
                alpha = rgba.pop();

            if ( includeAlpha ) {
                rgba.push( ~~( alpha * 255 ) );
            }

            return "#" + jQuery.map( rgba, function( v ) {

                // default to 0 when nulls exist
                v = ( v || 0 ).toString( 16 );
                return v.length === 1 ? "0" + v : v;
            } ).join( "" );
        },
        toString: function() {
            return this._rgba[ 3 ] === 0 ? "transparent" : this.toRgbaString();
        }
    } );
    color.fn.parse.prototype = color.fn;

// hsla conversions adapted from:
// https://code.google.com/p/maashaack/source/browse/packages/graphics/trunk/src/graphics/colors/HUE2RGB.as?r=5021

    function hue2rgb( p, q, h ) {
        h = ( h + 1 ) % 1;
        if ( h * 6 < 1 ) {
            return p + ( q - p ) * h * 6;
        }
        if ( h * 2 < 1 ) {
            return q;
        }
        if ( h * 3 < 2 ) {
            return p + ( q - p ) * ( ( 2 / 3 ) - h ) * 6;
        }
        return p;
    }

    spaces.hsla.to = function( rgba ) {
        if ( rgba[ 0 ] == null || rgba[ 1 ] == null || rgba[ 2 ] == null ) {
            return [ null, null, null, rgba[ 3 ] ];
        }
        var r = rgba[ 0 ] / 255,
            g = rgba[ 1 ] / 255,
            b = rgba[ 2 ] / 255,
            a = rgba[ 3 ],
            max = Math.max( r, g, b ),
            min = Math.min( r, g, b ),
            diff = max - min,
            add = max + min,
            l = add * 0.5,
            h, s;

        if ( min === max ) {
            h = 0;
        } else if ( r === max ) {
            h = ( 60 * ( g - b ) / diff ) + 360;
        } else if ( g === max ) {
            h = ( 60 * ( b - r ) / diff ) + 120;
        } else {
            h = ( 60 * ( r - g ) / diff ) + 240;
        }

        // chroma (diff) == 0 means greyscale which, by definition, saturation = 0%
        // otherwise, saturation is based on the ratio of chroma (diff) to lightness (add)
        if ( diff === 0 ) {
            s = 0;
        } else if ( l <= 0.5 ) {
            s = diff / add;
        } else {
            s = diff / ( 2 - add );
        }
        return [ Math.round( h ) % 360, s, l, a == null ? 1 : a ];
    };

    spaces.hsla.from = function( hsla ) {
        if ( hsla[ 0 ] == null || hsla[ 1 ] == null || hsla[ 2 ] == null ) {
            return [ null, null, null, hsla[ 3 ] ];
        }
        var h = hsla[ 0 ] / 360,
            s = hsla[ 1 ],
            l = hsla[ 2 ],
            a = hsla[ 3 ],
            q = l <= 0.5 ? l * ( 1 + s ) : l + s - l * s,
            p = 2 * l - q;

        return [
            Math.round( hue2rgb( p, q, h + ( 1 / 3 ) ) * 255 ),
            Math.round( hue2rgb( p, q, h ) * 255 ),
            Math.round( hue2rgb( p, q, h - ( 1 / 3 ) ) * 255 ),
            a
        ];
    };


    each( spaces, function( spaceName, space ) {
        var props = space.props,
            cache = space.cache,
            to = space.to,
            from = space.from;

        // makes rgba() and hsla()
        color.fn[ spaceName ] = function( value ) {

            // generate a cache for this space if it doesn't exist
            if ( to && !this[ cache ] ) {
                this[ cache ] = to( this._rgba );
            }
            if ( value === undefined ) {
                return this[ cache ].slice();
            }

            var ret,
                type = getType( value ),
                arr = ( type === "array" || type === "object" ) ? value : arguments,
                local = this[ cache ].slice();

            each( props, function( key, prop ) {
                var val = arr[ type === "object" ? key : prop.idx ];
                if ( val == null ) {
                    val = local[ prop.idx ];
                }
                local[ prop.idx ] = clamp( val, prop );
            } );

            if ( from ) {
                ret = color( from( local ) );
                ret[ cache ] = local;
                return ret;
            } else {
                return color( local );
            }
        };

        // makes red() green() blue() alpha() hue() saturation() lightness()
        each( props, function( key, prop ) {

            // alpha is included in more than one space
            if ( color.fn[ key ] ) {
                return;
            }
            color.fn[ key ] = function( value ) {
                var local, cur, match, fn,
                    vtype = getType( value );

                if ( key === "alpha" ) {
                    fn = this._hsla ? "hsla" : "rgba";
                } else {
                    fn = spaceName;
                }
                local = this[ fn ]();
                cur = local[ prop.idx ];

                if ( vtype === "undefined" ) {
                    return cur;
                }

                if ( vtype === "function" ) {
                    value = value.call( this, cur );
                    vtype = getType( value );
                }
                if ( value == null && prop.empty ) {
                    return this;
                }
                if ( vtype === "string" ) {
                    match = rplusequals.exec( value );
                    if ( match ) {
                        value = cur + parseFloat( match[ 2 ] ) * ( match[ 1 ] === "+" ? 1 : -1 );
                    }
                }
                local[ prop.idx ] = value;
                return this[ fn ]( local );
            };
        } );
    } );

// add cssHook and .fx.step function for each named hook.
// accept a space separated string of properties
    color.hook = function( hook ) {
        var hooks = hook.split( " " );
        each( hooks, function( _i, hook ) {
            jQuery.cssHooks[ hook ] = {
                set: function( elem, value ) {
                    var parsed, curElem,
                        backgroundColor = "";

                    if ( value !== "transparent" && ( getType( value ) !== "string" || ( parsed = stringParse( value ) ) ) ) {
                        value = color( parsed || value );
                        if ( !support.rgba && value._rgba[ 3 ] !== 1 ) {
                            curElem = hook === "backgroundColor" ? elem.parentNode : elem;
                            while (
                                ( backgroundColor === "" || backgroundColor === "transparent" ) &&
                                curElem && curElem.style
                                ) {
                                try {
                                    backgroundColor = jQuery.css( curElem, "backgroundColor" );
                                    curElem = curElem.parentNode;
                                } catch ( e ) {
                                }
                            }

                            value = value.blend( backgroundColor && backgroundColor !== "transparent" ?
                                backgroundColor :
                                "_default" );
                        }

                        value = value.toRgbaString();
                    }
                    try {
                        elem.style[ hook ] = value;
                    } catch ( e ) {

                        // wrapped to prevent IE from throwing errors on "invalid" values like 'auto' or 'inherit'
                    }
                }
            };
            jQuery.fx.step[ hook ] = function( fx ) {
                if ( !fx.colorInit ) {
                    fx.start = color( fx.elem, hook );
                    fx.end = color( fx.end );
                    fx.colorInit = true;
                }
                jQuery.cssHooks[ hook ].set( fx.elem, fx.start.transition( fx.end, fx.pos ) );
            };
        } );

    };

    color.hook( stepHooks );

    jQuery.cssHooks.borderColor = {
        expand: function( value ) {
            var expanded = {};

            each( [ "Top", "Right", "Bottom", "Left" ], function( _i, part ) {
                expanded[ "border" + part + "Color" ] = value;
            } );
            return expanded;
        }
    };

// Basic color names only.
// Usage of any of the other color names requires adding yourself or including
// jquery.color.svg-names.js.
    colors = jQuery.Color.names = {

        // 4.1. Basic color keywords
        aqua: "#00ffff",
        black: "#000000",
        blue: "#0000ff",
        fuchsia: "#ff00ff",
        gray: "#808080",
        green: "#008000",
        lime: "#00ff00",
        maroon: "#800000",
        navy: "#000080",
        olive: "#808000",
        purple: "#800080",
        red: "#ff0000",
        silver: "#c0c0c0",
        teal: "#008080",
        white: "#ffffff",
        yellow: "#ffff00",

        // 4.2.3. "transparent" color keyword
        transparent: [ null, null, null, 0 ],

        _default: "#ffffff"
    };


    /*!
     * jQuery UI Effects 1.13.1
     * http://jqueryui.com
     *
     * Copyright jQuery Foundation and other contributors
     * Released under the MIT license.
     * http://jquery.org/license
     */

//>>label: Effects Core
//>>group: Effects
    /* eslint-disable max-len */
//>>description: Extends the internal jQuery effects. Includes morphing and easing. Required by all other effects.
    /* eslint-enable max-len */
//>>docs: http://api.jqueryui.com/category/effects-core/
//>>demos: http://jqueryui.com/effect/


    var dataSpace = "ui-effects-",
        dataSpaceStyle = "ui-effects-style",
        dataSpaceAnimated = "ui-effects-animated";

    $.effects = {
        effect: {}
    };

    /******************************************************************************/
    /****************************** CLASS ANIMATIONS ******************************/
    /******************************************************************************/
    ( function() {

        var classAnimationActions = [ "add", "remove", "toggle" ],
            shorthandStyles = {
                border: 1,
                borderBottom: 1,
                borderColor: 1,
                borderLeft: 1,
                borderRight: 1,
                borderTop: 1,
                borderWidth: 1,
                margin: 1,
                padding: 1
            };

        $.each(
            [ "borderLeftStyle", "borderRightStyle", "borderBottomStyle", "borderTopStyle" ],
            function( _, prop ) {
                $.fx.step[ prop ] = function( fx ) {
                    if ( fx.end !== "none" && !fx.setAttr || fx.pos === 1 && !fx.setAttr ) {
                        jQuery.style( fx.elem, prop, fx.end );
                        fx.setAttr = true;
                    }
                };
            }
        );

        function camelCase( string ) {
            return string.replace( /-([\da-z])/gi, function( all, letter ) {
                return letter.toUpperCase();
            } );
        }

        function getElementStyles( elem ) {
            var key, len,
                style = elem.ownerDocument.defaultView ?
                    elem.ownerDocument.defaultView.getComputedStyle( elem, null ) :
                    elem.currentStyle,
                styles = {};

            if ( style && style.length && style[ 0 ] && style[ style[ 0 ] ] ) {
                len = style.length;
                while ( len-- ) {
                    key = style[ len ];
                    if ( typeof style[ key ] === "string" ) {
                        styles[ camelCase( key ) ] = style[ key ];
                    }
                }

                // Support: Opera, IE <9
            } else {
                for ( key in style ) {
                    if ( typeof style[ key ] === "string" ) {
                        styles[ key ] = style[ key ];
                    }
                }
            }

            return styles;
        }

        function styleDifference( oldStyle, newStyle ) {
            var diff = {},
                name, value;

            for ( name in newStyle ) {
                value = newStyle[ name ];
                if ( oldStyle[ name ] !== value ) {
                    if ( !shorthandStyles[ name ] ) {
                        if ( $.fx.step[ name ] || !isNaN( parseFloat( value ) ) ) {
                            diff[ name ] = value;
                        }
                    }
                }
            }

            return diff;
        }

// Support: jQuery <1.8
        if ( !$.fn.addBack ) {
            $.fn.addBack = function( selector ) {
                return this.add( selector == null ?
                    this.prevObject : this.prevObject.filter( selector )
                );
            };
        }

        $.effects.animateClass = function( value, duration, easing, callback ) {
            var o = $.speed( duration, easing, callback );

            return this.queue( function() {
                var animated = $( this ),
                    baseClass = animated.attr( "class" ) || "",
                    applyClassChange,
                    allAnimations = o.children ? animated.find( "*" ).addBack() : animated;

                // Map the animated objects to store the original styles.
                allAnimations = allAnimations.map( function() {
                    var el = $( this );
                    return {
                        el: el,
                        start: getElementStyles( this )
                    };
                } );

                // Apply class change
                applyClassChange = function() {
                    $.each( classAnimationActions, function( i, action ) {
                        if ( value[ action ] ) {
                            animated[ action + "Class" ]( value[ action ] );
                        }
                    } );
                };
                applyClassChange();

                // Map all animated objects again - calculate new styles and diff
                allAnimations = allAnimations.map( function() {
                    this.end = getElementStyles( this.el[ 0 ] );
                    this.diff = styleDifference( this.start, this.end );
                    return this;
                } );

                // Apply original class
                animated.attr( "class", baseClass );

                // Map all animated objects again - this time collecting a promise
                allAnimations = allAnimations.map( function() {
                    var styleInfo = this,
                        dfd = $.Deferred(),
                        opts = $.extend( {}, o, {
                            queue: false,
                            complete: function() {
                                dfd.resolve( styleInfo );
                            }
                        } );

                    this.el.animate( this.diff, opts );
                    return dfd.promise();
                } );

                // Once all animations have completed:
                $.when.apply( $, allAnimations.get() ).done( function() {

                    // Set the final class
                    applyClassChange();

                    // For each animated element,
                    // clear all css properties that were animated
                    $.each( arguments, function() {
                        var el = this.el;
                        $.each( this.diff, function( key ) {
                            el.css( key, "" );
                        } );
                    } );

                    // This is guarnteed to be there if you use jQuery.speed()
                    // it also handles dequeuing the next anim...
                    o.complete.call( animated[ 0 ] );
                } );
            } );
        };

        $.fn.extend( {
            addClass: ( function( orig ) {
                return function( classNames, speed, easing, callback ) {
                    return speed ?
                        $.effects.animateClass.call( this,
                            { add: classNames }, speed, easing, callback ) :
                        orig.apply( this, arguments );
                };
            } )( $.fn.addClass ),

            removeClass: ( function( orig ) {
                return function( classNames, speed, easing, callback ) {
                    return arguments.length > 1 ?
                        $.effects.animateClass.call( this,
                            { remove: classNames }, speed, easing, callback ) :
                        orig.apply( this, arguments );
                };
            } )( $.fn.removeClass ),

            toggleClass: ( function( orig ) {
                return function( classNames, force, speed, easing, callback ) {
                    if ( typeof force === "boolean" || force === undefined ) {
                        if ( !speed ) {

                            // Without speed parameter
                            return orig.apply( this, arguments );
                        } else {
                            return $.effects.animateClass.call( this,
                                ( force ? { add: classNames } : { remove: classNames } ),
                                speed, easing, callback );
                        }
                    } else {

                        // Without force parameter
                        return $.effects.animateClass.call( this,
                            { toggle: classNames }, force, speed, easing );
                    }
                };
            } )( $.fn.toggleClass ),

            switchClass: function( remove, add, speed, easing, callback ) {
                return $.effects.animateClass.call( this, {
                    add: add,
                    remove: remove
                }, speed, easing, callback );
            }
        } );

    } )();

    /******************************************************************************/
    /*********************************** EFFECTS **********************************/
    /******************************************************************************/

    ( function() {

        if ( $.expr && $.expr.pseudos && $.expr.pseudos.animated ) {
            $.expr.pseudos.animated = ( function( orig ) {
                return function( elem ) {
                    return !!$( elem ).data( dataSpaceAnimated ) || orig( elem );
                };
            } )( $.expr.pseudos.animated );
        }

        if ( $.uiBackCompat !== false ) {
            $.extend( $.effects, {

                // Saves a set of properties in a data storage
                save: function( element, set ) {
                    var i = 0, length = set.length;
                    for ( ; i < length; i++ ) {
                        if ( set[ i ] !== null ) {
                            element.data( dataSpace + set[ i ], element[ 0 ].style[ set[ i ] ] );
                        }
                    }
                },

                // Restores a set of previously saved properties from a data storage
                restore: function( element, set ) {
                    var val, i = 0, length = set.length;
                    for ( ; i < length; i++ ) {
                        if ( set[ i ] !== null ) {
                            val = element.data( dataSpace + set[ i ] );
                            element.css( set[ i ], val );
                        }
                    }
                },

                setMode: function( el, mode ) {
                    if ( mode === "toggle" ) {
                        mode = el.is( ":hidden" ) ? "show" : "hide";
                    }
                    return mode;
                },

                // Wraps the element around a wrapper that copies position properties
                createWrapper: function( element ) {

                    // If the element is already wrapped, return it
                    if ( element.parent().is( ".ui-effects-wrapper" ) ) {
                        return element.parent();
                    }

                    // Wrap the element
                    var props = {
                            width: element.outerWidth( true ),
                            height: element.outerHeight( true ),
                            "float": element.css( "float" )
                        },
                        wrapper = $( "<div></div>" )
                            .addClass( "ui-effects-wrapper" )
                            .css( {
                                fontSize: "100%",
                                background: "transparent",
                                border: "none",
                                margin: 0,
                                padding: 0
                            } ),

                        // Store the size in case width/height are defined in % - Fixes #5245
                        size = {
                            width: element.width(),
                            height: element.height()
                        },
                        active = document.activeElement;

                    // Support: Firefox
                    // Firefox incorrectly exposes anonymous content
                    // https://bugzilla.mozilla.org/show_bug.cgi?id=561664
                    try {
                        // eslint-disable-next-line no-unused-expressions
                        active.id;
                    } catch ( e ) {
                        active = document.body;
                    }

                    element.wrap( wrapper );

                    // Fixes #7595 - Elements lose focus when wrapped.
                    if ( element[ 0 ] === active || $.contains( element[ 0 ], active ) ) {
                        $( active ).trigger( "focus" );
                    }

                    // Hotfix for jQuery 1.4 since some change in wrap() seems to actually
                    // lose the reference to the wrapped element
                    wrapper = element.parent();

                    // Transfer positioning properties to the wrapper
                    if ( element.css( "position" ) === "static" ) {
                        wrapper.css( { position: "relative" } );
                        element.css( { position: "relative" } );
                    } else {
                        $.extend( props, {
                            position: element.css( "position" ),
                            zIndex: element.css( "z-index" )
                        } );
                        $.each( [ "top", "left", "bottom", "right" ], function( i, pos ) {
                            props[ pos ] = element.css( pos );
                            if ( isNaN( parseInt( props[ pos ], 10 ) ) ) {
                                props[ pos ] = "auto";
                            }
                        } );
                        element.css( {
                            position: "relative",
                            top: 0,
                            left: 0,
                            right: "auto",
                            bottom: "auto"
                        } );
                    }
                    element.css( size );

                    return wrapper.css( props ).show();
                },

                removeWrapper: function( element ) {
                    var active = document.activeElement;

                    if ( element.parent().is( ".ui-effects-wrapper" ) ) {
                        element.parent().replaceWith( element );

                        // Fixes #7595 - Elements lose focus when wrapped.
                        if ( element[ 0 ] === active || $.contains( element[ 0 ], active ) ) {
                            $( active ).trigger( "focus" );
                        }
                    }

                    return element;
                }
            } );
        }

        $.extend( $.effects, {
            version: "1.13.1",

            define: function( name, mode, effect ) {
                if ( !effect ) {
                    effect = mode;
                    mode = "effect";
                }

                $.effects.effect[ name ] = effect;
                $.effects.effect[ name ].mode = mode;

                return effect;
            },

            scaledDimensions: function( element, percent, direction ) {
                if ( percent === 0 ) {
                    return {
                        height: 0,
                        width: 0,
                        outerHeight: 0,
                        outerWidth: 0
                    };
                }

                var x = direction !== "horizontal" ? ( ( percent || 100 ) / 100 ) : 1,
                    y = direction !== "vertical" ? ( ( percent || 100 ) / 100 ) : 1;

                return {
                    height: element.height() * y,
                    width: element.width() * x,
                    outerHeight: element.outerHeight() * y,
                    outerWidth: element.outerWidth() * x
                };

            },

            clipToBox: function( animation ) {
                return {
                    width: animation.clip.right - animation.clip.left,
                    height: animation.clip.bottom - animation.clip.top,
                    left: animation.clip.left,
                    top: animation.clip.top
                };
            },

            // Injects recently queued functions to be first in line (after "inprogress")
            unshift: function( element, queueLength, count ) {
                var queue = element.queue();

                if ( queueLength > 1 ) {
                    queue.splice.apply( queue,
                        [ 1, 0 ].concat( queue.splice( queueLength, count ) ) );
                }
                element.dequeue();
            },

            saveStyle: function( element ) {
                element.data( dataSpaceStyle, element[ 0 ].style.cssText );
            },

            restoreStyle: function( element ) {
                element[ 0 ].style.cssText = element.data( dataSpaceStyle ) || "";
                element.removeData( dataSpaceStyle );
            },

            mode: function( element, mode ) {
                var hidden = element.is( ":hidden" );

                if ( mode === "toggle" ) {
                    mode = hidden ? "show" : "hide";
                }
                if ( hidden ? mode === "hide" : mode === "show" ) {
                    mode = "none";
                }
                return mode;
            },

            // Translates a [top,left] array into a baseline value
            getBaseline: function( origin, original ) {
                var y, x;

                switch ( origin[ 0 ] ) {
                    case "top":
                        y = 0;
                        break;
                    case "middle":
                        y = 0.5;
                        break;
                    case "bottom":
                        y = 1;
                        break;
                    default:
                        y = origin[ 0 ] / original.height;
                }

                switch ( origin[ 1 ] ) {
                    case "left":
                        x = 0;
                        break;
                    case "center":
                        x = 0.5;
                        break;
                    case "right":
                        x = 1;
                        break;
                    default:
                        x = origin[ 1 ] / original.width;
                }

                return {
                    x: x,
                    y: y
                };
            },

            // Creates a placeholder element so that the original element can be made absolute
            createPlaceholder: function( element ) {
                var placeholder,
                    cssPosition = element.css( "position" ),
                    position = element.position();

                // Lock in margins first to account for form elements, which
                // will change margin if you explicitly set height
                // see: http://jsfiddle.net/JZSMt/3/ https://bugs.webkit.org/show_bug.cgi?id=107380
                // Support: Safari
                element.css( {
                    marginTop: element.css( "marginTop" ),
                    marginBottom: element.css( "marginBottom" ),
                    marginLeft: element.css( "marginLeft" ),
                    marginRight: element.css( "marginRight" )
                } )
                    .outerWidth( element.outerWidth() )
                    .outerHeight( element.outerHeight() );

                if ( /^(static|relative)/.test( cssPosition ) ) {
                    cssPosition = "absolute";

                    placeholder = $( "<" + element[ 0 ].nodeName + ">" ).insertAfter( element ).css( {

                        // Convert inline to inline block to account for inline elements
                        // that turn to inline block based on content (like img)
                        display: /^(inline|ruby)/.test( element.css( "display" ) ) ?
                            "inline-block" :
                            "block",
                        visibility: "hidden",

                        // Margins need to be set to account for margin collapse
                        marginTop: element.css( "marginTop" ),
                        marginBottom: element.css( "marginBottom" ),
                        marginLeft: element.css( "marginLeft" ),
                        marginRight: element.css( "marginRight" ),
                        "float": element.css( "float" )
                    } )
                        .outerWidth( element.outerWidth() )
                        .outerHeight( element.outerHeight() )
                        .addClass( "ui-effects-placeholder" );

                    element.data( dataSpace + "placeholder", placeholder );
                }

                element.css( {
                    position: cssPosition,
                    left: position.left,
                    top: position.top
                } );

                return placeholder;
            },

            removePlaceholder: function( element ) {
                var dataKey = dataSpace + "placeholder",
                    placeholder = element.data( dataKey );

                if ( placeholder ) {
                    placeholder.remove();
                    element.removeData( dataKey );
                }
            },

            // Removes a placeholder if it exists and restores
            // properties that were modified during placeholder creation
            cleanUp: function( element ) {
                $.effects.restoreStyle( element );
                $.effects.removePlaceholder( element );
            },

            setTransition: function( element, list, factor, value ) {
                value = value || {};
                $.each( list, function( i, x ) {
                    var unit = element.cssUnit( x );
                    if ( unit[ 0 ] > 0 ) {
                        value[ x ] = unit[ 0 ] * factor + unit[ 1 ];
                    }
                } );
                return value;
            }
        } );

// Return an effect options object for the given parameters:
        function _normalizeArguments( effect, options, speed, callback ) {

            // Allow passing all options as the first parameter
            if ( $.isPlainObject( effect ) ) {
                options = effect;
                effect = effect.effect;
            }

            // Convert to an object
            effect = { effect: effect };

            // Catch (effect, null, ...)
            if ( options == null ) {
                options = {};
            }

            // Catch (effect, callback)
            if ( typeof options === "function" ) {
                callback = options;
                speed = null;
                options = {};
            }

            // Catch (effect, speed, ?)
            if ( typeof options === "number" || $.fx.speeds[ options ] ) {
                callback = speed;
                speed = options;
                options = {};
            }

            // Catch (effect, options, callback)
            if ( typeof speed === "function" ) {
                callback = speed;
                speed = null;
            }

            // Add options to effect
            if ( options ) {
                $.extend( effect, options );
            }

            speed = speed || options.duration;
            effect.duration = $.fx.off ? 0 :
                typeof speed === "number" ? speed :
                    speed in $.fx.speeds ? $.fx.speeds[ speed ] :
                        $.fx.speeds._default;

            effect.complete = callback || options.complete;

            return effect;
        }

        function standardAnimationOption( option ) {

            // Valid standard speeds (nothing, number, named speed)
            if ( !option || typeof option === "number" || $.fx.speeds[ option ] ) {
                return true;
            }

            // Invalid strings - treat as "normal" speed
            if ( typeof option === "string" && !$.effects.effect[ option ] ) {
                return true;
            }

            // Complete callback
            if ( typeof option === "function" ) {
                return true;
            }

            // Options hash (but not naming an effect)
            if ( typeof option === "object" && !option.effect ) {
                return true;
            }

            // Didn't match any standard API
            return false;
        }

        $.fn.extend( {
            effect: function( /* effect, options, speed, callback */ ) {
                var args = _normalizeArguments.apply( this, arguments ),
                    effectMethod = $.effects.effect[ args.effect ],
                    defaultMode = effectMethod.mode,
                    queue = args.queue,
                    queueName = queue || "fx",
                    complete = args.complete,
                    mode = args.mode,
                    modes = [],
                    prefilter = function( next ) {
                        var el = $( this ),
                            normalizedMode = $.effects.mode( el, mode ) || defaultMode;

                        // Sentinel for duck-punching the :animated pseudo-selector
                        el.data( dataSpaceAnimated, true );

                        // Save effect mode for later use,
                        // we can't just call $.effects.mode again later,
                        // as the .show() below destroys the initial state
                        modes.push( normalizedMode );

                        // See $.uiBackCompat inside of run() for removal of defaultMode in 1.14
                        if ( defaultMode && ( normalizedMode === "show" ||
                            ( normalizedMode === defaultMode && normalizedMode === "hide" ) ) ) {
                            el.show();
                        }

                        if ( !defaultMode || normalizedMode !== "none" ) {
                            $.effects.saveStyle( el );
                        }

                        if ( typeof next === "function" ) {
                            next();
                        }
                    };

                if ( $.fx.off || !effectMethod ) {

                    // Delegate to the original method (e.g., .show()) if possible
                    if ( mode ) {
                        return this[ mode ]( args.duration, complete );
                    } else {
                        return this.each( function() {
                            if ( complete ) {
                                complete.call( this );
                            }
                        } );
                    }
                }

                function run( next ) {
                    var elem = $( this );

                    function cleanup() {
                        elem.removeData( dataSpaceAnimated );

                        $.effects.cleanUp( elem );

                        if ( args.mode === "hide" ) {
                            elem.hide();
                        }

                        done();
                    }

                    function done() {
                        if ( typeof complete === "function" ) {
                            complete.call( elem[ 0 ] );
                        }

                        if ( typeof next === "function" ) {
                            next();
                        }
                    }

                    // Override mode option on a per element basis,
                    // as toggle can be either show or hide depending on element state
                    args.mode = modes.shift();

                    if ( $.uiBackCompat !== false && !defaultMode ) {
                        if ( elem.is( ":hidden" ) ? mode === "hide" : mode === "show" ) {

                            // Call the core method to track "olddisplay" properly
                            elem[ mode ]();
                            done();
                        } else {
                            effectMethod.call( elem[ 0 ], args, done );
                        }
                    } else {
                        if ( args.mode === "none" ) {

                            // Call the core method to track "olddisplay" properly
                            elem[ mode ]();
                            done();
                        } else {
                            effectMethod.call( elem[ 0 ], args, cleanup );
                        }
                    }
                }

                // Run prefilter on all elements first to ensure that
                // any showing or hiding happens before placeholder creation,
                // which ensures that any layout changes are correctly captured.
                return queue === false ?
                    this.each( prefilter ).each( run ) :
                    this.queue( queueName, prefilter ).queue( queueName, run );
            },

            show: ( function( orig ) {
                return function( option ) {
                    if ( standardAnimationOption( option ) ) {
                        return orig.apply( this, arguments );
                    } else {
                        var args = _normalizeArguments.apply( this, arguments );
                        args.mode = "show";
                        return this.effect.call( this, args );
                    }
                };
            } )( $.fn.show ),

            hide: ( function( orig ) {
                return function( option ) {
                    if ( standardAnimationOption( option ) ) {
                        return orig.apply( this, arguments );
                    } else {
                        var args = _normalizeArguments.apply( this, arguments );
                        args.mode = "hide";
                        return this.effect.call( this, args );
                    }
                };
            } )( $.fn.hide ),

            toggle: ( function( orig ) {
                return function( option ) {
                    if ( standardAnimationOption( option ) || typeof option === "boolean" ) {
                        return orig.apply( this, arguments );
                    } else {
                        var args = _normalizeArguments.apply( this, arguments );
                        args.mode = "toggle";
                        return this.effect.call( this, args );
                    }
                };
            } )( $.fn.toggle ),

            cssUnit: function( key ) {
                var style = this.css( key ),
                    val = [];

                $.each( [ "em", "px", "%", "pt" ], function( i, unit ) {
                    if ( style.indexOf( unit ) > 0 ) {
                        val = [ parseFloat( style ), unit ];
                    }
                } );
                return val;
            },

            cssClip: function( clipObj ) {
                if ( clipObj ) {
                    return this.css( "clip", "rect(" + clipObj.top + "px " + clipObj.right + "px " +
                        clipObj.bottom + "px " + clipObj.left + "px)" );
                }
                return parseClip( this.css( "clip" ), this );
            },

            transfer: function( options, done ) {
                var element = $( this ),
                    target = $( options.to ),
                    targetFixed = target.css( "position" ) === "fixed",
                    body = $( "body" ),
                    fixTop = targetFixed ? body.scrollTop() : 0,
                    fixLeft = targetFixed ? body.scrollLeft() : 0,
                    endPosition = target.offset(),
                    animation = {
                        top: endPosition.top - fixTop,
                        left: endPosition.left - fixLeft,
                        height: target.innerHeight(),
                        width: target.innerWidth()
                    },
                    startPosition = element.offset(),
                    transfer = $( "<div class='ui-effects-transfer'></div>" );

                transfer
                    .appendTo( "body" )
                    .addClass( options.className )
                    .css( {
                        top: startPosition.top - fixTop,
                        left: startPosition.left - fixLeft,
                        height: element.innerHeight(),
                        width: element.innerWidth(),
                        position: targetFixed ? "fixed" : "absolute"
                    } )
                    .animate( animation, options.duration, options.easing, function() {
                        transfer.remove();
                        if ( typeof done === "function" ) {
                            done();
                        }
                    } );
            }
        } );

        function parseClip( str, element ) {
            var outerWidth = element.outerWidth(),
                outerHeight = element.outerHeight(),
                clipRegex = /^rect\((-?\d*\.?\d*px|-?\d+%|auto),?\s*(-?\d*\.?\d*px|-?\d+%|auto),?\s*(-?\d*\.?\d*px|-?\d+%|auto),?\s*(-?\d*\.?\d*px|-?\d+%|auto)\)$/,
                values = clipRegex.exec( str ) || [ "", 0, outerWidth, outerHeight, 0 ];

            return {
                top: parseFloat( values[ 1 ] ) || 0,
                right: values[ 2 ] === "auto" ? outerWidth : parseFloat( values[ 2 ] ),
                bottom: values[ 3 ] === "auto" ? outerHeight : parseFloat( values[ 3 ] ),
                left: parseFloat( values[ 4 ] ) || 0
            };
        }

        $.fx.step.clip = function( fx ) {
            if ( !fx.clipInit ) {
                fx.start = $( fx.elem ).cssClip();
                if ( typeof fx.end === "string" ) {
                    fx.end = parseClip( fx.end, fx.elem );
                }
                fx.clipInit = true;
            }

            $( fx.elem ).cssClip( {
                top: fx.pos * ( fx.end.top - fx.start.top ) + fx.start.top,
                right: fx.pos * ( fx.end.right - fx.start.right ) + fx.start.right,
                bottom: fx.pos * ( fx.end.bottom - fx.start.bottom ) + fx.start.bottom,
                left: fx.pos * ( fx.end.left - fx.start.left ) + fx.start.left
            } );
        };

    } )();

    /******************************************************************************/
    /*********************************** EASING ***********************************/
    /******************************************************************************/

    ( function() {

// Based on easing equations from Robert Penner (http://www.robertpenner.com/easing)

        var baseEasings = {};

        $.each( [ "Quad", "Cubic", "Quart", "Quint", "Expo" ], function( i, name ) {
            baseEasings[ name ] = function( p ) {
                return Math.pow( p, i + 2 );
            };
        } );

        $.extend( baseEasings, {
            Sine: function( p ) {
                return 1 - Math.cos( p * Math.PI / 2 );
            },
            Circ: function( p ) {
                return 1 - Math.sqrt( 1 - p * p );
            },
            Elastic: function( p ) {
                return p === 0 || p === 1 ? p :
                    -Math.pow( 2, 8 * ( p - 1 ) ) * Math.sin( ( ( p - 1 ) * 80 - 7.5 ) * Math.PI / 15 );
            },
            Back: function( p ) {
                return p * p * ( 3 * p - 2 );
            },
            Bounce: function( p ) {
                var pow2,
                    bounce = 4;

                while ( p < ( ( pow2 = Math.pow( 2, --bounce ) ) - 1 ) / 11 ) {}
                return 1 / Math.pow( 4, 3 - bounce ) - 7.5625 * Math.pow( ( pow2 * 3 - 2 ) / 22 - p, 2 );
            }
        } );

        $.each( baseEasings, function( name, easeIn ) {
            $.easing[ "easeIn" + name ] = easeIn;
            $.easing[ "easeOut" + name ] = function( p ) {
                return 1 - easeIn( 1 - p );
            };
            $.easing[ "easeInOut" + name ] = function( p ) {
                return p < 0.5 ?
                    easeIn( p * 2 ) / 2 :
                    1 - easeIn( p * -2 + 2 ) / 2;
            };
        } );

    } )();

    var effect = $.effects;


    /*!
     * jQuery UI Effects Slide 1.13.1
     * http://jqueryui.com
     *
     * Copyright jQuery Foundation and other contributors
     * Released under the MIT license.
     * http://jquery.org/license
     */

//>>label: Slide Effect
//>>group: Effects
//>>description: Slides an element in and out of the viewport.
//>>docs: http://api.jqueryui.com/slide-effect/
//>>demos: http://jqueryui.com/effect/


    var effectsEffectSlide = $.effects.define( "slide", "show", function( options, done ) {
        var startClip, startRef,
            element = $( this ),
            map = {
                up: [ "bottom", "top" ],
                down: [ "top", "bottom" ],
                left: [ "right", "left" ],
                right: [ "left", "right" ]
            },
            mode = options.mode,
            direction = options.direction || "left",
            ref = ( direction === "up" || direction === "down" ) ? "top" : "left",
            positiveMotion = ( direction === "up" || direction === "left" ),
            distance = options.distance ||
                element[ ref === "top" ? "outerHeight" : "outerWidth" ]( true ),
            animation = {};

        $.effects.createPlaceholder( element );

        startClip = element.cssClip();
        startRef = element.position()[ ref ];

        // Define hide animation
        animation[ ref ] = ( positiveMotion ? -1 : 1 ) * distance + startRef;
        animation.clip = element.cssClip();
        animation.clip[ map[ direction ][ 1 ] ] = animation.clip[ map[ direction ][ 0 ] ];

        // Reverse the animation if we're showing
        if ( mode === "show" ) {
            element.cssClip( animation.clip );
            element.css( ref, animation[ ref ] );
            animation.clip = startClip;
            animation[ ref ] = startRef;
        }

        // Actually animate
        element.animate( animation, {
            queue: false,
            duration: options.duration,
            easing: options.easing,
            complete: done
        } );
    } );
} );


(function(factory) {
        "use strict";
        if (typeof define === 'function' && define.amd) {
            define(['jquery'], factory);
        } else if (window.jQuery && !window.jQuery.fn.DistributionNetwork) {
            factory(window.jQuery);
        }
    }
    (function($) {
        'use strict';

        // DistributionNetwork object
        var DistributionNetwork = function(container, options) {
            this._default_options = {
                network_options: {
                    width: '800px',
                    height: '759px',
                    layout: {randomSeed: 0},
                    edges: {
                        arrowStrikethrough: false,
                        arrows: {
                            to: {enabled: true, scaleFactor:1, type:'arrow'},
                        },
                        shadow: {
                            enabled: true,
                            size: 7,
                            x: 3,
                            y: 3
                        }
                    },
                    physics:{
                        barnesHut: {
                            gravitationalConstant: -10000,
                            centralGravity: 0.3,
                            springLength: 150,
                            springConstant: 0.02,
                            damping: 0.09,
                            avoidOverlap: 0
                        },
                        repulsion: {
                            centralGravity: 0.2,
                            springLength: 200,
                            springConstant: 0.02,
                            nodeDistance: 200,
                            damping: 0.15
                        },

                        solver: 'barnesHut'
                    },
                    nodes: {
                        shadow: {
                            enabled: true,
                            size: 7,
                            x: 3,
                            y: 3
                        }
                    },
                    groups: {
                        'root': {
                            shape: 'icon',
                            icon: {
                                face: '"Font Awesome 5 Free"',
                                code: '\uf111',
                                color: '#000000',
                                size: 50,
                            },
                            font: {size: 30},
                            color: '#000000',
                        },
                        'org-only': {
                            shape: 'icon',
                            icon: {
                                face: '"Font Awesome 5 Free"',
                                code: '\uf2c2',
                                color: '#ff0000',
                                size: 30
                            },
                            font: {
                                size: 14, // px
                                color: '#ff0000',
                                background: 'rgba(255, 255, 255, 0.7)'
                            },
                            color: '#ff0000',
                        },
                        'root-this-community': {
                            shape: 'icon',
                            icon: {
                                face: '"Font Awesome 5 Free"',
                                code: '\uf1e1',
                                color: '#ff9725',
                                size: 70
                            },
                            font: {
                                size: 18, // px
                                color: '#ff9725',
                                background: 'rgba(255, 255, 255, 0.7)'
                            },
                            color: '#ff9725',
                        },
                        'this-community': {
                            font: {color: 'white'},
                            color: '#ff9725',
                            shape: 'box',
                            margin: 3
                        },
                        'otherOrg': {
                            shape: 'ellipse',
                            font: {color: 'white', size: 24},
                            color: '#ff9725',
                            margin: 3
                        },
                        'root-connected-community': {
                            shape: 'icon',
                            icon: {
                                face: '"Font Awesome 5 Free"',
                                code: '\uf0e8',
                                color: '#9b6e1b',
                                size: 70
                            },
                            font: {
                                size: 18, // px
                                color: '#9b6e1b',
                                background: 'rgba(255, 255, 255, 0.7)'
                            },
                            color: '#9b6e1b',
                        },
                        'connected-community': {
                            shape: 'image',
                            image: '/img/orgs/MISP.png'
                        },
                        'web': {
                            shape: 'icon',
                            icon: {
                                face: '"Font Awesome 5 Free"',
                                code: '\uf0ac',
                                color: '#007d20',
                                size: 70
                            },
                            font: {
                                size: 18, // px
                                color: '#007d20',
                                background: 'rgba(255, 255, 255, 0.7)'
                            },
                            color: '#007d20',
                        },
                        'root-sharing-group': {
                            shape: 'icon',
                            icon: {
                                face: '"Font Awesome 5 Free"',
                                code: '\uf0c0',
                                color: '#1369a0',
                                size: 70
                            },
                            font: {
                                size: 18, // px
                                color: '#1369a0',
                                background: 'rgba(255, 255, 255, 0.7)'
                            },
                            color: '#1369a0',
                        }
                    }
                },
                EDGE_LENGTH_HUB: 300,
                THRESHOLD_ORG_NUM: 30
            };

            this.container = $(container);
            this._validateOptions(options);

            this.network_wrapper = false;
            this.options = $.extend({}, this._default_options, options);

            this.event_distribution = this.options.event_distribution;
            this.scope_id = this.options.scope_id;
            this.distributionData = this.options.distributionData;
            this.network;
            this.nodes_distri;
            this.edges_distri;
            this.cacheAddedOrgName = {};

            this._constructUI();
            this._registerListener();
        };

        DistributionNetwork.prototype = {
            constructor: DistributionNetwork,

            _validateOptions: function(options) {
                if (options.event_distribution === undefined) {
                    // try to fetch is from the container
                    var event_distribution = this.container.data('event-distribution');
                    var event_distribution_name = this.container.data('event-distribution-name');
                    if (event_distribution !== undefined && event_distribution_name !== undefined) {
                        options.event_distribution = event_distribution;
                        options.event_distribution_name = event_distribution_name;
                        this._adjust_sharing_numbers(options)
                    } else {
                        throw "Event distribution or Org not set";
                    }
                }

                if (options.distributionData === undefined) {
                    throw "Distribution data not set";
                }
                if (options.scope_id === undefined) {
                    // try to fetch is from the container
                    var scope_id = this.container.data('scope-id');
                    if (scope_id !== undefined) {
                        options.scope_id = scope_id;
                    } else {
                        throw "Scope id is not set";
                    }
                }
            },

            _adjust_sharing_numbers: function (options) {
                var sum = options.distributionData.event.reduce(function(pv, cv) { return pv + cv; }, 0);
                if (sum == 0) { // if event does not contain anything (or we don't know about its content)
                    options.distributionData.event[options.event_distribution] = 1;
                }
                if (options.event_distribution == 4) {
                    options.distributionData.additionalDistributionInfo[4].push(options.event_distribution_name);
                }
            },

            _registerListener: function() {
                var that = this;
                this.container.click(function() {
                    $('#sharingNetworkWrapper').toggle('slide', {direction: 'right'}, 300);
                    that._construct_network();

                    $('body').off('keyup.distributionNetwork').on('keyup.distributionNetwork', function(e) {
                        if (e.keyCode == 27) { // ESC
                            $('body').off('keyup.distributionNetwork');
                            that.dismissNetwork();
                        }
                    });
                });

            },

            dismissNetwork: function() {
                $('#sharingNetworkWrapper').hide('slide', {direction: 'right'}, 300);
            },

            _constructUI: function() {
                var that = this;
                if ($('#sharingNetworkWrapper').length > 0) {
                    return; // Wrapper already exists
                }

                var allow_interactive_picking = $('#attributes_div table tr').length > 0;

                var $div = '<div id="sharingNetworkWrapper" class="fixedRightPanel hidden">'
                    + '<div class="eventgraph_header" style="border-radius: 5px; display: flex;">'
                    + '<it class="fa fa-circle-o" style="margin: auto 10px; font-size: x-large"></it>'
                    + '<input type="text" id="sharingNetworkTargetId" class="center-in-network-header network-typeahead" style="width: 200px;" disabled>';
                if (allow_interactive_picking) {
                    $div += '<div class="form-group" style="margin: auto 10px;"><div class="checkbox">'
                        + '<label style="user-select: none;"><input id="interactive_picking_mode" type="checkbox" title="Click on a element to see how it is distributed" style="margin-top: 4px;">Enable interactive picking mode</label>'
                        + '</div></div>'
                }
                $div += '<select type="text" id="sharingNetworkOrgFinder" class="center-in-network-header network-typeahead sharingNetworkOrgFinder" style="width: 200px;"></select>'
                    + '<button id="closeButton" type="button" class="close" style="margin: 1px 5px; right: 0px; position: absolute;">×</button>'
                    + '</div><div id="advancedSharingNetwork"></div></div>';
                $div = $($div);
                this.network_wrapper = $div;
                $div.find('#closeButton').click(function() {
                    that.dismissNetwork();
                });
                $('body').append($div);
            },

            _construct_network: function(target_distribution, scope_text, overwriteSg) {
                var that = this;
                if (this.network !== undefined) {
                    this.network.destroy();
                    this.cacheAddedOrgName = {};
                }
                if (scope_text == undefined) {
                    scope_text = 'Event ' + this.options.scope_id;
                }
                $('#sharingNetworkTargetId').val(scope_text);

                this.nodes_distri = new vis.DataSet([
                    {id: 'root', group: 'root', label: scope_text, x: 0, y: 0, fixed: true, mass: 20},
                    {id: this.distributionData.additionalDistributionInfo[0][0], label: this.distributionData.additionalDistributionInfo[0][0], group: 'org-only'},

                ]);
                this.edges_distri = new vis.DataSet([
                    {from: 'root', to: this.distributionData.additionalDistributionInfo[0][0], length: 30, width: 3},
                ]);
                if (target_distribution === undefined || target_distribution == 5) {
                    target_distribution = this.event_distribution;
                }

                if (target_distribution !== 0) {
                    // Event always restrict propagation (sharing group is a special case)
                    var temp_target_disti = target_distribution;
                    if (target_distribution !== 4 && temp_target_disti >= this.event_distribution) {
                        while (temp_target_disti >= this.event_distribution) {
                            var toID = false;
                            switch (temp_target_disti) {
                                case 0:
                                    break;
                                case 1:
                                    toID = 'this-community';
                                    break;
                                case 2:
                                    toID = 'connected-community';
                                    break;
                                case 3:
                                    toID = 'all-community';
                                    break;
                                case 4:
                                    toID = 'sharing-group';
                                    break;
                                default:
                                    break;
                            }
                            var edgeData = {from: 'root', to: toID, width: 3};
                            if (temp_target_disti != this.event_distribution) {
                                edgeData.label = 'X';
                                edgeData.title = 'The distribution of the Event restricts the distribution level of this element';
                                edgeData.font = {
                                    size: 50,
                                    color: '#ff0000',
                                    strokeWidth: 6,
                                    strokeColor: '#ff0000'
                                };
                            }
                            if (toID !== false) {
                                this.edges_distri.add(edgeData);
                            }
                            temp_target_disti--;
                        }
                    } else {
                        switch (temp_target_disti) {
                            case 0:
                                break;
                            case 1:
                                toID = 'this-community';
                                break;
                            case 2:
                                toID = 'connected-community';
                                break;
                            case 3:
                                toID = 'all-community';
                                break;
                            case 4:
                                toID = 'sharing-group';
                                break;
                            default:
                                break;
                        }
                        var edgeData = {from: 'root', to: toID, width: 3};
                        if (toID !== false) {
                            this.edges_distri.add(edgeData);
                        }
                    }
                }

                var nodesToAdd = [];
                var edgesToAdd = [];
                this.cacheAddedOrgName[this.distributionData.additionalDistributionInfo[0][0]] = 1;

                // Community
                if (target_distribution >= 1 && target_distribution != 4
                    && (this.distributionData.event[1] > 0 || this.distributionData.event[2] > 0 || this.distributionData.event[3] > 0)
                ) {
                    nodesToAdd.push({id: 'this-community', label: 'This community', group: 'root-this-community'});
                    this._inject_this_community_org(nodesToAdd, edgesToAdd, this.distributionData.additionalDistributionInfo[1], 'this-community', 'this-community');
                }
                // Connected Community
                if (target_distribution >= 2 && target_distribution != 4
                    && (this.distributionData.event[2] > 0 || this.distributionData.event[3] > 0)
                ) {
                    nodesToAdd.push({id: 'connected-community', label: 'Connected communities', group: 'root-connected-community'});
                    this.distributionData.additionalDistributionInfo[2].forEach(function(orgName) {
                        if (orgName === 'This community') {
                            edgesToAdd.push({from: 'connected-community', to: 'this-community', length: that.options.EDGE_LENGTH_HUB});
                        } else {
                            nodesToAdd.push({
                                id: 'connected-community_' + orgName,
                                label: orgName,
                                group: 'connected-community'
                            });
                            edgesToAdd.push({from: 'connected-community', to: 'connected-community_' + orgName});
                        }
                    });
                }

                // All Community
                if (target_distribution >= 3 && target_distribution != 4
                    && this.distributionData.event[3] > 0
                ) {
                    nodesToAdd.push({id: 'all-community', label: 'All communities', group: 'web'});
                    this.distributionData.additionalDistributionInfo[3].forEach(function(orgName) {
                        if (orgName === 'This community') {
                            edgesToAdd.push({from: 'all-community', to: 'this-community', length: that.options.EDGE_LENGTH_HUB});
                        } else if (orgName === 'All other communities') {
                            edgesToAdd.push({from: 'all-community', to: 'connected-community', length: that.options.EDGE_LENGTH_HUB});
                        }
                    });
                }
                // Sharing Group
                if (this.distributionData.event[4] > 0) {
                    this.distributionData.allSharingGroup.forEach(function(sg) {
                        var sgName = sg.SharingGroup.name;
                        if (overwriteSg === undefined) { // if overwriteSg not set, use the one from the event
                            overwriteSg = that.distributionData.additionalDistributionInfo[4];
                        }
                        if (overwriteSg.indexOf(sgName) == -1) {
                            return true;
                        }

                        nodesToAdd.push({
                            id: 'sharing-group_' + sgName,
                            label: sgName,
                            group: 'root-sharing-group'
                        });
                        edgesToAdd.push({from: 'root', to: 'sharing-group_' + sgName, width: 3});
                        sg.SharingGroupOrg.forEach(function(org) {
                            var sgOrgName = org.Organisation.name;
                            if (that.cacheAddedOrgName[sgOrgName] === undefined) {
                                nodesToAdd.push({
                                    id: sgOrgName,
                                    label: sgOrgName,
                                    group: 'sharing-group'
                                });
                                that.cacheAddedOrgName[sgOrgName] = 1;
                            }
                            edgesToAdd.push({
                                from: 'sharing-group_' + sgName,
                                to: sgOrgName,
                                arrows: {
                                    to: { enabled: false }
                                },
                                color: { opacity: 0.4 }
                            });
                        });
                    });
                }

                var options = '<option></option>';
                $('#sharingNetworkOrgFinder').empty();
                Object.keys(this.cacheAddedOrgName).forEach(function(org) {
                    options += '<option value="'+org+'">'+org+'</option>';
                });
                $('#sharingNetworkOrgFinder').append(options)
                .trigger('chosen:updated')
                .chosen({
                    inherit_select_classes: true,
                    no_results_text: "Focus to an organisation",
                    placeholder_text_single: "Focus to an organisation",
                    allow_single_deselect: true
                })
                .off('change')
                .on('change', function(evt, params) {
                    if (this.value !== '') {
                        if (that.nodes_distri.get(this.value) !== null) {
                            that.network.focus(this.value, {animation: true});
                            that.network.selectNodes([this.value]);
                        }
                    } else {
                        that.network.fit({animation: true})
                    }
                });

                this.nodes_distri.add(nodesToAdd);
                this.edges_distri.add(edgesToAdd);
                var data = { nodes: this.nodes_distri, edges: this.edges_distri };
                this.network = new vis.Network(document.getElementById('advancedSharingNetwork'), data, this.options.network_options);

                this.network.on("dragStart", function (params) {
                    params.nodes.forEach(function(nodeId) {
                        that.nodes_distri.update({id: nodeId, fixed: {x: false, y: false}});
                    });
                });
                this.network.on("dragEnd", function (params) {
                    params.nodes.forEach(function(nodeId) {
                        that.nodes_distri.update({id: nodeId, fixed: {x: true, y: true}});
                    });
                });

                $('#interactive_picking_mode').off('change').on('change', function(e) {
                    var target_id = $(this).val();
                    if (this.checked) {
                        that._toggleRowListener(true);
                    } else {
                        that._toggleRowListener(false);
                        that._construct_network(this.event_distribution)
                    }
                });
            },

            _toggleRowListener: function(toAdd) {
                var that = this;
                if (toAdd) {
                    var $table = $('#attributes_div table tr');
                    if ($table.length == 0) {
                        return;
                    }
                    $table.off('click.advancedSharing').on('click.advancedSharing', function() {
                        var $row = $(this);
                        var clicked_type = $row.attr('id').split('_')[0];
                        var clicked_id = $row.attr('id').split('_')[1];
                        var $dist_cell = $row.find('div').filter(function() {
                            return $(this).attr('id') !== undefined && $(this).attr('id').includes(clicked_id+'_distribution');
                        });

                        var distribution_value;
                        var overwriteSg;
                        switch ($dist_cell.text().trim()) {
                            case 'Organisation':
                                distribution_value = 0;
                                break;
                            case 'Community':
                                distribution_value = 1;
                                break;
                            case 'Connected':
                                distribution_value = 2;
                                break;
                            case 'All':
                                distribution_value = 3;
                                break;
                            case 'Inherit':
                                distribution_value = 5;
                                if (that.event_distribution == 4) {
                                    overwriteSg = that.event_distribution_text.trim();
                                }
                                break;
                            default:
                                distribution_value = 4;
                                overwriteSg = $dist_cell.text().trim();
                                break
                        }
                        that._construct_network(distribution_value, clicked_type+' '+clicked_id, [overwriteSg]);
                    });
                } else {
                    $('#attributes_div table tr').off('click.advancedSharing');
                }
            },

            _inject_this_community_org: function(nodesToAdd, edgesToAdd, orgs, group, root) {
                var that = this;
                for (var i=0; i<orgs.length; i++) {
                    if (i > this.options.THRESHOLD_ORG_NUM) {
                        nodesToAdd.push({
                            id: 'OthersOrgRemaining',
                            label: (orgs.length - i) + " Organisations remaining",
                            group: 'otherOrg',
                            size: 50,
                        });
                        that.cacheAddedOrgName[orgName] = 1;
                        edgesToAdd.push({
                            from: root,
                            to: 'OthersOrgRemaining',
                            arrows: {
                                to: { enabled: false }
                            },
                            color: { opacity: 0.4 }
                        });
                        break;
                    } else {
                        var orgName = orgs[i];
                        if (that.cacheAddedOrgName[orgName] === undefined) {
                            nodesToAdd.push({
                                id: orgName,
                                label: orgName,
                                group: group
                            });
                            that.cacheAddedOrgName[orgName] = 1;
                        }
                        edgesToAdd.push({
                            from: root,
                            to: orgName,
                            arrows: {
                                to: { enabled: false }
                            },
                            color: { opacity: 0.4 }
                        });
                    }
                }
            },

        };

        $.distributionNetwork = DistributionNetwork;
        $.fn.distributionNetwork = function(option) {
            var pickedArgs = arguments;

            return this.each(function() {
                var $this = $(this),
                    inst = $this.data('distributionNetwork'),
                    options = ((typeof option === 'object') ? option : {});
                if ((!inst) && (typeof option !== 'string')) {
                    $this.data('distributionNetwork', new DistributionNetwork(this, options));
                } else {
                    if (typeof option === 'string') {
                        inst[option].apply(inst, Array.prototype.slice.call(pickerArgs, 1));
                    }
                }
            });
        };

        $.fn.distributionNetwork.constructor = DistributionNetwork;
    }));
