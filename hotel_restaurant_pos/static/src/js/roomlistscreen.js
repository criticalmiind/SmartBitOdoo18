/* @odoo-module */
    // console.log("Screens  =======   ");
    // const { Gui } = require('point_of_sale.Gui');
    import { PosCollection } from '@point_of_sale/app/store/models';
    import { usePos } from "@point_of_sale/app/store/pos_hook";
    import { renderToElement } from '@web/core/utils/render';
    import { AbstractAwaitablePopup } from "@point_of_sale/app/popup/abstract_awaitable_popup";
    var models = PosCollection

    // var core = require('web.core');
    // var QWeb = core.qweb;
    import {_t} from "@web/core/l10n/translation";
    import { Component, onMounted, useState, useRef, useContext  } from "@odoo/owl";
    // const PosComponent = require('point_of_sale.PosComponent');
    import { registry } from "@web/core/registry";
    // const Registries = require('point_of_sale.Registries');

    console.log('kkkkkkkkkkkkkkkkkkkkkkkkk',this.pos);
    class RoomListScreenWidget extends AbstractAwaitablePopup {
        static template = 'RoomListScreenWidget';
            setup() {
                this.pos = usePos();
                console.log('ffffffffffffffffffffffffffff',this.pos)
                super.setup(...arguments);
                this.loading = useState({
                    message: 'Loading',
                    skipButtonIsShown: false,
                });
    
                this.mainScreen = useState({ name: null, component: null });
                this.mainScreenProps = {};
    
                this.tempScreen = useState({ isShown: false, name: null, component: null });
                this.tempScreenProps = {};
    
                this.progressbar = useRef('progressbar');
                onMounted(() => {
                    this.show();
                    this.room_line()
                });
                
                }
//         constructor() {
//             console.log('ddddddddddddddddddddddddddddddddd');
//             super(...arguments);
//             
//             this.loading = useState({
//                 message: 'Loading',
//                 skipButtonIsShown: false,
//             });

//             this.mainScreen = useState({ name: null, component: null });
//             this.mainScreenProps = {};

//             this.tempScreen = useState({ isShown: false, name: null, component: null });
//             this.tempScreenProps = {};

//             this.progressbar = useRef('progressbar');
//             onMounted(() => {
//                 this.show();
//             });

//         }
        destroy() {
            super.destroy(...arguments);
            this.pos.destroy();
        }
        catchError(error) {
            console.error(error);
        }
        render_room_list(rooms) {
            console.log('haiiiiiiiiiiiiiiiiiiiiiiiiiiiii');
            var d = new Date();
            var current_date = new Date(String(d.getFullYear()) + "-" + String(d.getMonth() + 1) + "-" + String(d.getDate())).setHours(0, 0, 0, 0);
            var contents = document.querySelector('.room-list-contents');

            contents.innerHTML = "";
            var hotel_folio = this.pos.hotel_folio;
            for (var i = 0, len = Math.min(rooms.length, 1000); i < len; i++) {
               console.log(rooms[i].folio_id)
                var room = rooms[i];
                var checkin = room.checkin_date;
                var checkin_dt = new Date(checkin.split(" ")[0]).setHours(0, 0, 0, 0);
                var checkout = room.checkout_date;
                var checkout_dt = new Date(checkout.split(" ")[0]).setHours(0, 0, 0, 0);
                
                if (checkin_dt <= current_date && checkout_dt >= current_date) {
                    console.log('loading............................')
                    for (var j = 0; j < hotel_folio.length; j++) {
                        if ((hotel_folio[j].state === 'draft')&&(room.folio_id[0] === hotel_folio[j].id)) {
                            if (room) {
                                console.log('Helloooooooooooooooooooooo');
                                var roomline_html = renderToElement('RoomLine', { room: rooms[i] });
                                console.log('passssssssssssssssssssssssssssss',roomline_html)
                                // var roomline = document.createElement('tbody');
                                // roomline.innerHTML = roomline_html;
                                // console.log('ggggggggggggroomlineggggggggggggggggg',roomline)
                                // roomline = roomline.childNodes[0];
                                // console.log('*************roomline2******************',roomline)
                            }
                            // console.log('roommmmmmmmmmmmmmmmm',this.old_room)
                            // if (room === this.old_room) {
                            //     // roomline.classList.add('highlight');
                            //     roomline.addClass('room-line')
                            //     console.log('*************roomline2******************',roomline.classList)
                            // } else {
                            //     // roomline.classList.remove('highlight');
                            //     roomline.remove('room-line')
                            // }
                            contents.appendChild(roomline_html);
                        }
                    }
                }
            }
        }
        back() {
            this.pos.showScreen('PaymentScreen');
        }
        show() {
            var poss =this.pos
            var self = this;
            // this._super();
            // this.renderElement();
            this.details_visible = false;

            // this.$('.back').click(function () {
            //     self.gui.back();
            // });

            // this.$('.next').click(function () {
            //     self.save_changes();
            //     self.gui.back();    // FIXME HUH ?
            // });
            console.log(this.pos);
            var rooms = this.pos.hotel_folio_line_;
            var hotel_folio = this.pos.hotel_folio
            console.log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!',this.pos)
            /**
                Loading partner id and partner name in room object
            */
            for (var i = 0, len = Math.min(rooms.length, 1000); i < len; i++) {
                var room = rooms[i];
                for (var j = 0; j < hotel_folio.length; j++) {
                    if (hotel_folio[j].state === 'draft') {
                        if (room.folio_id[0] === hotel_folio[j].id) {
                            room['partner_id'] = hotel_folio[j].partner_id[0];
                            room['partner_name'] = hotel_folio[j].partner_id[1];
                            break;
                        }
                    }
                }
            }

            /**
                Rendering Room object
            */
            this.render_room_list(rooms);
            

            $(function () {
                $(document).delegate('.room-line', 'click', function (event) {
                    var line_data;
                    var room_name;
                    var customer_name;
                    var pricelist_name;
                    var folio_line_id;
                    var folio_ids;
                    var partner;
                    console.log('!!!!!!!!!!!!!!!!!!!this2!!!!!!!!!!!!!!!',this)
                    console.log('posssssssssss',poss
                    )
        
                    var partner_id = $($(this).children()[2]).data('cust-id');
        
                    poss.get_order().set_partner(poss.db.get_partner_by_id(parseInt(partner_id)));
                    customer_name = $($(this).children()[2]).text();
                    room_name = $($(this).children()[0]).text();
                    folio_ids = $($(this).children()[1]).data('folio-id');
                    folio_line_id = parseInt($(this).data('id'));
                    poss.get_order().set_folio_ids(folio_ids);
                    poss.get_order().set_folio_line_id(folio_line_id);
                    poss.get_order().set_room_name(room_name);
                    $('.js_room_name').text(room_name ? room_name : _t('Room'));
                    $('.js_customer_name').text(customer_name ? customer_name : _t('Customer'));
                    $('.set-customer').text(customer_name ? customer_name : _t('Customer'));
                    partner = self.pos.db.get_partner_by_id(partner_id)
                    poss.get_order().updatePricelistAndFiscalPosition(partner)
                    self.back();
            });
        });
            
        };
        room_line() {
            console.log('hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh',this.pos)
        }
        
    }
    // RoomListScreenWidget.template = 'RoomListScreenWidget';
    registry.category("pos_screens").add("RoomListScreenWidget", RoomListScreenWidget);

    // registry.category('views').add('RoomListScreenWidget', RoomListScreenWidget);

    return RoomListScreenWidget;
