/** @odoo-module **/

// odoo.define('hotel_online.cart', function (require) {
//     'use strict';

$(document).ready(function () {

//    $('.sheet-hide').each(function(index) {
//      var divId = 'toggle-div' + index;
//       console.log('Clicked button ID111111111111:', divId);
//      $(this).attr('id', divId);
//    });
//
//    $('.open-button').each(function(index) {
//      var buttonId = 'sheet-div-' + index;
//       console.log('Clicked button ID111111111111:', buttonId);
//      $(this).attr('data-id', buttonId);
//    });
//
//    $('.open-button').click(function(e, index) {
//        e.preventDefault();
//        var buttonId = $(this).data('id');
//        var Id = buttonId[buttonId.length - 1]
//        Id = '#toggle-div' + Id
//        var sheetDiv = $('.sheet-div').filter('[data-id="' + buttonId + '"]');
//        $(Id).find('#sheet-div').slideToggle();
//    });
//
//    $('.hide-button').each(function(index) {
//      var buttonId = 'sheet-div-' + index;
//       console.log('Clicked button ID111111111111:', buttonId);
//      $(this).attr('data-id', buttonId);
//    });
//
//    $('.hide-button').click(function(e) {
//        e.preventDefault();
//
//        var buttonId = $(this).data('id');
//        var Id = buttonId[buttonId.length - 1]
//        Id = '#toggle-div' + Id
//        var sheetDiv = $('.sheet-div').filter('[data-id="' + buttonId + '"]');
//        $(Id).find('#sheet-div').slideToggle();
//    });

    $('.orders').each(function (index) {
        var divId = 'dropdown-div' + index;
        console.log('Clicked button ID111111111111:', divId);
        $(this).attr('id', divId);
    });

    $('.room-tab').each(function (index) {
        var buttonId = 'room-div-' + index;
        console.log('Clicked button ID111111111111:', buttonId);
        $(this).attr('data-id', buttonId);
    });

    $('.room-tab').click(function (e, index) {
        e.preventDefault();
        var buttonId = $(this).data('id');
        var Id = buttonId[buttonId.length - 1]
        Id = '#dropdown-div' + Id
        console.log('+++++++++++++++ID:', Id);
        console.log('Clicked button ID:', buttonId);
        var roomDiv = $('.room-div').filter('[data-id="' + buttonId + '"]');
        console.log('roomDivId@@@@@@@:', roomDiv);
        console.log('+++++', $(roomDiv).find(`[id='room-div']`))
        console.log('---------------', $(Id))
        console.log('---------------', $(Id).find('#room-div'))
        $(Id).find('#room-div').slideToggle();
        $(Id).find('#services-div').slideUp();
        $(Id).find('#amenities-div').slideUp();
    });

    $('.services-tab').each(function (index) {
        var buttonId = 'services-div-' + index;
//           console.log('Clicked button ID111111111111:', buttonId);
        $(this).attr('data-id', buttonId);
    });

    $('.services-tab').click(function (e) {
        e.preventDefault();
        var buttonId = $(this).data('id');
        var Id = buttonId[buttonId.length - 1]
        Id = '#dropdown-div' + Id
        $(Id).find('#services-div').slideToggle();
        $(Id).find('#room-div').slideUp();
        $(Id).find('#amenities-div').slideUp();
    });

    $('.amenities-tab').each(function (index) {
        var buttonId = 'amenities-div-' + index;
        console.log('Clicked button ID111111111111:', buttonId);
        $(this).attr('data-id', buttonId);
    });

    $('.amenities-tab').click(function (e) {
        e.preventDefault();
        var buttonId = $(this).data('id');
        var Id = buttonId[buttonId.length - 1]
        Id = '#dropdown-div' + Id
        $(Id).find('#amenities-div').slideToggle();
        $(Id).find('#services-div').slideUp();
        $(Id).find('#room-div').slideUp();
    });

//    document.addEventListener('DOMContentLoaded', function() {
//        const hideButton = document.querySelector('.hide-button');
//        const informationSheet = document.querySelector('.information-sheet');
//
//        hideButton.addEventListener('click', function() {
//            informationSheet.style.display = 'none';
//        });
//    });

//    $('.dashboard-tab').click(function(e) {
//    e.preventDefault();
//    $.ajax({
//        type: "POST",
//        url: "/hotel/dashboard",
//        data: {},
//        success: function(response) {
//            console.log(response);
//        }
//    });
//    $('#facilities-div, #services-div, #amenities-div').slideUp();
//});

});

// });