
var ver_timer;

function checkVersion() {
    ver_timer = setTimeout("srcVersion()", 3000);
}

function imgVerComplete() {
    var img = document.getElementById("check_image");
    clearTimeout(ver_timer);
    if (img.height == 0) {
        img.src = "/img/version_0.5.png";
    }
    else {
        //ver_timer = setTimeout("currentVersion()", 600);
    }
}

function srcVersion() {
    var img = document.getElementById("check_image");
    img.src = "http://projects.xplico.org/version/xplico_0.5.8.png";
    ver_timer = setTimeout("imgVerComplete()", 400);
}

function lastVersion() {
    var img = document.getElementById("check_image");
    img.src = "http://projects.xplico.org/version/xplico_0.5.8.png";
    ver_timer = setTimeout(" currentVersion()", 5000);
}

function currentVersion() {
    var img = document.getElementById("check_image");
    img.src = "/img/version_0.5.png";
    ver_timer = setTimeout("lastVersion()", 5000);
}
