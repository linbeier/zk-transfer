$("#in").click(function(){
        var data = {};
        data['name'] = "hello";
        $.ajax({
            type: 'GET',
            url: '{{url_for("app.recieve_name")}}',
            data: data,
            dataType: 'json',
            success: function(data) {
                console.log(data);
                alert(data.name+data.age);
            },
            error: function(xhr, type) {
                console.log(xhr);
                console.log(type);
            }
        })
});

// $(function() {
//     function submit_form(e) {
//         $.getJSON($SCRIPT_ROOT + '/add', {
//             a: $('input[name="a"]').val(),
//             b: $('input[name="b"]').val(),
//             now: new Date().getTime()
//         },
//         function(data) {
//             $('#result').text(data.result);
//         });
//     };
//     // 绑定click事件
//     $('#calculate').bind('click', submit_form);
// });



