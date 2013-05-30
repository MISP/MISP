/*jslint browser: true*/
/*global $, jQuery*/

(function(){
    "use strict";

    $(".datepicker").datepicker({
        format: 'yyyy-mm-dd',

    });

    $(".span12").on('change', ".updateCIMBL", function(){
        $.ajax({
            url: $(this).parent().attr('action'),
            type: 'POST',
            dataType: 'json',
            data: $(this).parent().serialize(),
            success: function(data){
                if(data.msg !== null){
                    alert(data.msg);
                }
            }
        });
    });

}());