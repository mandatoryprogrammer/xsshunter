function send_contact_message() {
    contact_object = {}
    contact_object[ "email" ] = $( "#email" ).val();
    contact_object[ "name" ] = $( "#name" ).val();
    contact_object[ "body" ] = $( "#body" ).val();
    api_request( "POST", "/api/contactus", contact_object, function( response ){
        if( response["success"] == true ) {
            $(".contact_us_form_success_message").fadeIn();
            clear_contact_form();
            setTimeout(function() {
                $(".contact_us_form_success_message").fadeOut();
            }, 5000);
        }
    })
}

function clear_contact_form() {
    $( "#email" ).val("");
    $( "#name" ).val("");
    $( "#body" ).val("");
    $( "#name" ).select();
}

$( ".contact_us_button" ).click(function() {
    send_contact_message();
});
