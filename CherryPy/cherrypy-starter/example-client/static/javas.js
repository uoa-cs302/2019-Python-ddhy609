
$(document).ready(function(){
    //Feed
    $("#tabFeed").on('click', function(){
     
    });

    //Messages
    $("#tabMessages").on('click', function(){
        /*code-source: https://www.pair.com/support/kb/how-to-use-jquery-to-show-hide-a-form-on-click/ */
        /*$("#messageBox").toggle()*/
    });

    //Form information send
    $('form').on('submit', function(event) {
        // Prevent the page from reloading
        //event.preventDefault();
        
        // Set the text-output span to the value of the first input
        var $input = $(this).find('input');
        var input = $input.val();
        
        $('#text-output').text("You typed: " + input);

        $.ajax({
            type: "POST",
            url: "/tx_broadcast",
            data: "message="+input,
            error : function(){
                window.alert("Couldn't send message")
            }
        })

      /*   var xhr = new XMLHttpRequest();
        xhr.open('POST','/tx_broadcast',true);
        //xhr.withCredentials = false;
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.send("message="+input); */
        return false;
    });

    //Account Info
    $("#tabAccountInfo").on('click', function(){
       
    });

    //Settings
    $("#tabSettings").on('click', function(){
        
    });

    //Home
    $("#tabHome").on('click', function(){
        
    });
});