$( ".signup_button" ).click( function() {
    register_account();
});

$(function() {
    $('input[id=domain]').keyup(function() {
        if (this.value.match(/[^a-zA-Z0-9]/g)) {
            this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');
        }
    });
});

function register_account() {
    USER = {}
    USER.username = $( "#username" ).val();
    USER.full_name = $( "#full_name" ).val();
    USER.domain = $( "#domain" ).val();
    USER.pgp_key = $( "#pgp-key" ).val();
    USER.email = $( "#email" ).val();
    USER.password = $( "#password" ).val();
    USER.invite_code = $( "#invite_code" ).val();
    api_request( "POST", "/api/register", USER, function( response ) {
        if( response["success"] == true ) {
            CSRF_TOKEN = response["csrf_token"];
            localStorage.setItem( "CSRF_TOKEN", CSRF_TOKEN );
            window.location = "/app";
        } else {
            $( ".bad_signup_text_fields" ).text( response["invalid_fields"] );
            $( ".bad_signup_dialogue" ).fadeIn();
            setTimeout( function() {
                $( ".bad_signup_dialogue" ).fadeOut();
            }, 5000);
        }
    });
}
$('[data-toggle="popover"]').popover({trigger: 'hover','placement': 'top'});
