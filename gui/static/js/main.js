/*
 * JavaScript for the general website
 */
$( document ).ready(function() {
    $( ".loading_bar" ).fadeOut();
    prettyPrint();
});

function hide_loading_bar() {
    $( ".loading_bar" ).fadeOut();
}

function show_loading_bar() {
    $( ".loading_bar" ).fadeIn();
}

function set_loading_bar() {

}

/*
 * Main XSS Hunter JavaScript
 * ( for the actual app )
 */
API_SERVER = "//" + document.domain.toString().replace( "www", "api" );
CSRF_TOKEN = "";
USER = {};

function api_request( method, path, data, callback ) {
    show_loading_bar();
    header_data = {};

    if( CSRF_TOKEN != "" ) {
        header_data["X-CSRF-Token"] = CSRF_TOKEN;
    }

    if( method == "GET" ) {
        content_type = "application/x-www-form-urlencoded"
        send_data = $.param( data );
    } else {
        content_type = "application/json; charset=utf-8"
        send_data = JSON.stringify( data );
    }

    $.ajax({
        url: API_SERVER + path,
        type: method,
        headers: header_data,
        data: send_data,
        xhrFields: {
            withCredentials: true
        },
        contentType: content_type,
        dataType: "json",
        success: function (data) {
            hide_loading_bar();
            callback( data );
        },
        error: function (data) {
            hide_loading_bar();
            callback({
                "error": true,
            });
        }
    });
}
