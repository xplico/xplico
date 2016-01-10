/*
 * jQuery File Upload Plugin JS Example 6.7
 * https://github.com/blueimp/jQuery-File-Upload
 *
 * Copyright 2010, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * http://www.opensource.org/licenses/MIT
 */

/*jslint nomen: true, unparam: true, regexp: true */
/*global $, window, document */


var filewav_num = 0;


function wavtbl() {
    $.getJSON('server/php/index.php?_method=WAV', function (result) {
        if (result && result.length) {
            if (result.length > filewav_num) {
                if (filewav_num == 0)
                    $('#wav_title').fadeOut(0).html('WAV Files:').fadeIn();
                
                $('#filelstwav').empty();
                $('#filelstwav').append(tmpl("template-wav", result));
                $('#filelstwav .template-download').addClass('in');
            }
            $("#filewav button").click(function() {
                $(this).parent().parent().slideUp().remove();
                $.get($(this).attr("data-url")+"&_method=DELETE");
                filewav_num--;
            });
            filewav_num = result.length;
        }
        else {
            $('#wav_title').fadeOut().empty();
        }
    });
    setTimeout("wavtbl()", 3000);
}

$(function () {
    'use strict';

    // Initialize the jQuery File Upload widget:
    $('#fileupload').fileupload();

    // Enable iframe cross-domain access via redirect option:
    $('#fileupload').fileupload(
        'option',
        'redirect',
        window.location.href.replace(
            /\/[^\/]*$/,
            '/cors/result.html?%s'
        )
    );

    $('#fileupload').fileupload('option', {
        maxFileSize: 5000000,
        autoUpload: true,
        maxNumberOfFiles: 5,
        acceptFileTypes: /(\.|\/)(cap|pcap)$/i
    });
    // Upload server status check for browsers with CORS support:
    if ($.support.cors) {
        $.ajax({
            type: 'HEAD'
        }).fail(function () {
            $('<span class="alert alert-error"/>')
                .text('Upload server currently unavailable - ' +
                        new Date())
                .appendTo('#fileupload');
        });
    }

    // Load existing files:
    $('#fileupload').each(function () {
        var that = this;
        $.getJSON(this.action, function (result) {
            if (result && result.length) {
                $(that).fileupload('option', 'done')
                    .call(that, null, {result: result});
            }
        });
    });
    
    wavtbl();
    setTimeout("wavtbl()", 10000);
});
