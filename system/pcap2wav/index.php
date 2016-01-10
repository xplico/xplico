<!DOCTYPE HTML>
<!--
/*
 * jQuery File Upload Plugin Demo 6.9
 * https://github.com/blueimp/jQuery-File-Upload
 *
 * Copyright 2010, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * http://www.opensource.org/licenses/MIT
 */
-->
<?php
$ip = $_SERVER['REMOTE_ADDR'];
$session_dir = dirname($_SERVER['SCRIPT_FILENAME']).'/server/php/files/'.$ip.'/';
if (isset($_REQUEST['_newsession'])) {
    mkdir($session_dir);
    touch($session_dir.'/ses');
}

if (is_file($session_dir.'/ses')) {
    $new_ses = 'hiden';
    $run_ses = '';
}
else {
    $new_ses = '';
    $run_ses = 'hiden';
}
?>

<html lang="en">
<head>
<meta charset="utf-8">
<title>PCAP2WAV RTP2WAV</title>
<meta name="description" content="rtp and pcap converter for audio codecs">
<meta name="viewport" content="width=device-width">
<!-- Bootstrap CSS Toolkit styles -->
<link rel="stylesheet" href="css/bootstrap.min.css">
<!-- Generic page styles -->
<link rel="stylesheet" href="css/style.css">
<!-- Bootstrap styles for responsive website layout, supporting different screen sizes -->
<link rel="stylesheet" href="css/bootstrap-responsive.min.css">
<!-- Bootstrap CSS fixes for IE6 -->
<!--[if lt IE 7]><link rel="stylesheet" href="http://blueimp.github.com/cdn/css/bootstrap-ie6.min.css"><![endif]-->
<!-- CSS to style the file input field as button and adjust the Bootstrap progress bars -->
<link rel="stylesheet" href="css/jquery.fileupload-ui.css">
<!-- Shim to make HTML5 elements usable in older Internet Explorer versions -->
<!--[if lt IE 9]><script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script><![endif]-->
</head>
<body>
<div class="navbar navbar-fixed-top">
    <div class="navbar-inner">
        <div class="container">
            <a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </a>
            <a class="brand" href="http://pcap2wav.xplico.org">PCAP2WAV</a>
            <div class="nav-collapse">
                <ul class="nav">
                    <li class="active"><a href="#">Demo</a></li>
                    <li><a href="http://www.xplico.org">Xplico</a></li>
                    <li><a href="http://www.capanalysis.net">CapAnalysis</a></li>
                    <li><a href="mailto:xplico[at]iserm.com">Contact us</a></li>
                </ul>
            </div>
        </div>
    </div>
</div>
<div class="container">
    <div class="page-header">
        <h2>PCAP2WAV converts RTP streams to WAV files</h2>
    </div>
    <div class="<?php echo $run_ses; ?>">
    <div class="row">
    <div class="span7">
    <div class="well">
    <p><strong>Codecs supported</strong>: G711ulaw, G711alaw, G722, G729, G723, G726 and <strong>RTAudio (x-msrta: Real Time Audio)</strong>.<br/>PCAP2WAV is an <a href="http://www.xplico.org">Xplico</a> customization and it runs in <strong>Linux</strong>.<br/>Try it now, <strong>drag & drop</strong> here the <strong>PCAP file</strong>.<br/><strong>This session is visible only from your IP</strong> (<?php echo $ip; ?>).</p>
    </div>
    </div>
    <div class="span5">
    <h4>Demo rules:</h4>
    <ul>
        <li>Only network files (<strong>CAP, PCAP</strong>) are allowed.</li>
        <li>The maximum file size for uploads is <strong>5 MB</strong>.</li>
        <li>Uploaded files will be deleted automatically at <strong>00:00 GMT</strong>.</li>
        <li>You can <strong>drag &amp; drop</strong> files from your desktop on this webpage with Google Chrome, Mozilla Firefox and Apple Safari.</li>
    </ul>
    </div>
    </div>
    <!-- The file upload form used as target for the file upload widget -->
    <div class="row">
    <div class="span7">
    <form id="fileupload" action="server/php/" method="POST" enctype="multipart/form-data">
        <!-- The fileupload-buttonbar contains buttons to add/delete files and start/cancel the upload -->
        <div class="row fileupload-buttonbar">
            <div class="span7">
                <!-- The fileinput-button span is used to style the file input field as button -->
                <span class="btn btn-success fileinput-button">
                    <i class="icon-plus icon-white"></i>
                    <span>Add files...</span>
                    <input type="file" name="files[]" multiple>
                </span>
                <button type="button" class="btn btn-danger delete">
                    <i class="icon-trash icon-white"></i>
                    <span>Delete</span>
                </button>
                <input type="checkbox" class="toggle">
            </div>
            <!-- The global progress information -->
            <div class="span5 fileupload-progress fade">
                <!-- The global progress bar -->
                <div class="progress progress-success progress-striped active" role="progressbar" aria-valuemin="0" aria-valuemax="100">
                    <div class="bar" style="width:0%;"></div>
                </div>
                <!-- The extended global progress information -->
                <div class="progress-extended">&nbsp;</div>
            </div>
        </div>
        <!-- The loading indicator is shown during file processing -->
        <div class="fileupload-loading"></div>
        <br>
        <!-- The table listing the files available for upload/download -->
        <table role="presentation" class="table table-striped"><tbody class="files" id="filelst" ></tbody></table>
    </form>
    </div>
    <div class="span5">
    <h4 id="wav_title"></h4>
    <div id="filewav">
        <!-- The table listing the files available for download -->
        <table role="presentation" class="table table-striped"><tbody class="files" id="filelstwav" ></tbody></table>
    </div>
    </div>
    </div>
    </div>
    <div class="<?php echo $new_ses; ?>">
    <div class="row">
    <div class="span6">
    <div class="well">
       <p>A <strong>new Session</strong> and all its data (uploaded and decoded) are <strong>visible</strong> only <strong>from your IP</strong> (<?php echo $ip; ?>).<br/>
       <strong>To create a new session click the button below</strong>.
       </p>
       <a class="btn btn-success" href="index.php?_newsession=ok">Create a new  session</a>
    </div>
    </div>
    <div class="span6">
<div class="well">
       <p><strong>Codecs supported</strong>: G711ulaw, G711alaw, G722, G729, G723, G726 and <strong>RTAudio (x-msrta: Real Time Audio)</strong>.<br/>PCAP2WAV is an <a href="http://www.xplico.org">Xplico</a> customization and it runs in <strong>Linux</strong>.</p>
    </div>
    </div>
    </div>
    </div>
</div>
<!-- The template to display files available for upload -->
<script id="template-upload" type="text/x-tmpl">
{% for (var i=0, file; file=o.files[i]; i++) { %}
    <tr class="template-upload fade">
        <td class="preview"><span class="fade"></span></td>
        <td class="name"><span>{%=file.name%}</span></td>
        <td class="size"><span>{%=o.formatFileSize(file.size)%}</span></td>
        {% if (file.error) { %}
            <td class="error" colspan="2"><span class="label label-important">{%=locale.fileupload.error%}</span> {%=locale.fileupload.errors[file.error] || file.error%}</td>
        {% } else if (o.files.valid && !i) { %}
            <td>
                <div class="progress progress-success progress-striped active" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="bar" style="width:0%;"></div></div>
            </td>
            <td class="start">{% if (!o.options.autoUpload) { %}
                <button class="btn btn-primary">
                    <span>{%=locale.fileupload.start%}</span>
                </button>
            {% } %}</td>
        {% } else { %}
            <td colspan="2"></td>
        {% } %}
        <td class="cancel">{% if (!i) { %}
            <button class="btn btn-warning">
                <span>{%=locale.fileupload.cancel%}</span>
            </button>
        {% } %}</td>
    </tr>
{% } %}
</script>
<!-- The template to display files available for download -->
<script id="template-download" type="text/x-tmpl">
{% for (var i=0, file; file=o.files[i]; i++) { %}
    <tr class="template-download fade">
        {% if (file.error) { %}
            <td></td>
            <td class="name"><span>{%=file.name%}</span></td>
            <td class="size"><span>{%=o.formatFileSize(file.size)%}</span></td>
            <td class="error" colspan="2"><span class="label label-important">{%=locale.fileupload.error%}</span> {%=locale.fileupload.errors[file.error] || file.error%}</td>
        {% } else { %}
            <td class="name">
                <a href="{%=file.url%}" title="{%=file.name%}" rel="{%=file.thumbnail_url&&'gallery'%}" download="{%=file.name%}">{%=file.name%}</a>
            </td>
            <td class="size"><span>{%=o.formatFileSize(file.size)%}</span></td>
            <td colspan="2"></td>
        {% } %}
        <td class="delete">
            <button class="btn btn-danger" data-type="{%=file.delete_type%}" data-url="{%=file.delete_url%}">
                <span>{%=locale.fileupload.destroy%}</span>
            </button>
            <input type="checkbox" name="delete" value="1">
        </td>
    </tr>
{% } %}
</script>

<!-- The template to display files available for download -->
<script id="template-wav" type="text/x-tmpl">
{% for (var i=0, file; file=o[i]; i++) { %}
    <tr class="template-download fade">
            <td class="name">
                <a href="{%=file.url%}" title="{%=file.name%}" download="{%=file.name%}">{%=file.name%}</a>
            </td>
            <td class="size"><span>{%=file.size%}</span></td>
        <td class="delete">
            <button class="btn btn-danger" data-type="{%=file.delete_type%}" data-url="{%=file.delete_url%}">
                <span>{%=locale.fileupload.destroy%}</span>
            </button>
        </td>
    </tr>
{% } %}
</script>
<script src="js/jquery-1.7.2.min.js"></script>
<!-- The jQuery UI widget factory, can be omitted if jQuery UI is already included -->
<script src="js/vendor/jquery.ui.widget.js"></script>
<!-- The Templates plugin is included to render the upload/download listings -->
<script src="js/tmpl.min.js"></script>
<script src="js/bootstrap.min.js"></script>
<!-- The Iframe Transport is required for browsers without support for XHR file uploads -->
<script src="js/jquery.iframe-transport.js"></script>
<!-- The basic File Upload plugin -->
<script src="js/jquery.fileupload.js"></script>
<!-- The File Upload file processing plugin -->
<script src="js/jquery.fileupload-fp.js"></script>
<!-- The File Upload user interface plugin -->
<script src="js/jquery.fileupload-ui.js"></script>
<!-- The localization script -->
<script src="js/locale.js"></script>
<!-- The main application script -->
<script src="js/main.js"></script>
<!-- The XDomainRequest Transport is included for cross-domain file deletion for IE8+ -->
<!--[if gte IE 8]><script src="js/cors/jquery.xdr-transport.js"></script><![endif]-->
</body> 
</html>
