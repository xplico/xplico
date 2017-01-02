
var http_request = false;
var url_s;

function makeRequest(url) {
    
    http_request = false;
    
    if (window.XMLHttpRequest) { // Mozilla, Safari,...
        http_request = new XMLHttpRequest();
        if (http_request.overrideMimeType) {
            http_request.overrideMimeType('text/xml');
        }
    } else if (window.ActiveXObject) { // IE
        try {
            http_request = new ActiveXObject("Msxml2.XMLHTTP");
        } catch (e) {
            try {
                http_request = new ActiveXObject("Microsoft.XMLHTTP");
            } catch (e) {}
        }
    }
    
    if (!http_request) {
        alert('Giving up :( Cannot create an XMLHTTP instance');
        return false;
    }
    http_request.onreadystatechange = alertContents;
    http_request.open('GET', url, true);
    http_request.send(null);
    url_s = url;
    
}

function alertContents() {
    
    if (http_request.readyState == 4) {
        if (http_request.status == 200) {
            document.getElementById("contenuto").innerHTML = http_request.responseText;
            document.getElementById("displ").innerHTML = "<img src=\""+url_s+"\" width=50 > </img>";
        } else {
            alert('There was a problem with the request.');
        }
    }
    
}
