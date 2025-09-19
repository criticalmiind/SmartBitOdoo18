$(document).ready(function () {
    $.urlParam = function (name) {
        console.log(name);
        var results = new RegExp('[/?&]' + name + '=([^&#]*)').exec(window.location.href);
        console.log("Results", results)
        return results;
    }
    var date = new Date();
    var from_date_day = date.getDate();
    var to_date_day = date.getDate() + 1;
    var month = date.getMonth() + 1;
    var year = date.getFullYear();
    if (month < 10) month = "0" + month;
    if (from_date_day < 10) from_date_day = "0" + from_date_day;
    if (to_date_day < 10) to_date_day = "0" + to_date_day;
    $("#from_date").attr("value", year + "-" + month + "-" + from_date_day);
    $("#to_date").attr("value", year + "-" + month + "-" + to_date_day);
    console.log("After IFFFFFFFFFFFF==>>", from_date)
    var from_date = $('#from_date').val()
    console.log("from_date==>>", from_date)
    var to_date = $('#to_date').val()
    console.log("to_date==>>", to_date)

    $("#from_date").change(function () {
        var changed_from_date = $('#from_date').val().split("-");
        if ([1, 3, 5, 7, 8, 10, 12].includes(parseInt(changed_from_date[1])) && parseInt(changed_from_date[2]) === 31) {
            if (parseInt(changed_from_date[1]) === 12) {
                var new_year = parseInt(changed_from_date[0]) + 1
                $("#to_date").attr("value", new_year.toString() + "-01-01");
            } else {
                var new_month = parseInt(changed_from_date[1]) + 1;
                if (new_month < 10) new_month = "0" + new_month.toString();
                $("#to_date").attr("value", year + "-" + new_month + "-01");
            }
        } else if ([4, 6, 9, 11].includes(parseInt(changed_from_date[1])) && parseInt(changed_from_date[2]) === 30) {
            var new_month = parseInt(changed_from_date[1]) + 1;
            if (new_month < 10) new_month = "0" + new_month.toString();
            $("#to_date").attr("value", year + "-" + new_month + "-01");
        } else if (parseInt(changed_from_date[1]) === 2 && parseInt(changed_from_date[2]) === 29) {
            var new_month = parseInt(changed_from_date[1]) + 1;
            if (new_month < 10) new_month = "0" + new_month.toString();
            $("#to_date").attr("value", year + "-" + new_month + "-01");
        } else if (parseInt(changed_from_date[1]) === 2 && parseInt(changed_from_date[2]) === 28) {
            var new_month = parseInt(changed_from_date[1]) + 1;
            if (new_month < 10) new_month = "0" + new_month.toString();
            $("#to_date").attr("value", year + "-" + new_month + "-01");
        } else {
            var new_to_date_day = parseInt(changed_from_date[2]) + 1;
            if (new_to_date_day < 10) new_to_date_day = "0" + new_to_date_day.toString();
            $("#to_date").attr("value", year + "-" + changed_from_date[1] + "-" + new_to_date_day);
        }
    });
    var minDate = new Date();
    $('#datePicker').datepicker({
        format: 'mm/dd/yyyy',
        minDate: minDate,
        setDate: new Date(),
        "autoclose": true,
    }).on('changeDate', function (e) {
    });

    var checkin = $('#dpd1').datepicker({
        startDate: new Date(),

    }).on('changeDate', function (ev) {
        var to_date = $.urlParam('to_date');
        if (to_date === null) {
        var date2 = $('#dpd1').datepicker('getDate', '+1d');
            date2.setDate(date2.getDate() + 1);
        } else {
            var date2 = decodeURIComponent(to_date[1])
        }
        var checkout = $('#dpd2').datepicker({
            startDate: date2
        }).datepicker('setDate', date2);
    }).datepicker('setDate', from_date);

});