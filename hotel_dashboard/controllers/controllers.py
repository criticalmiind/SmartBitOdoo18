# -*- coding: utf-8 -*-
# from odoo import http


# class HotelDashboard(http.Controller):
#     @http.route('/hotel_dashboard/hotel_dashboard', auth='public')
#     def index(self, **kw):
#         return "Hello, world"

#     @http.route('/hotel_dashboard/hotel_dashboard/objects', auth='public')
#     def list(self, **kw):
#         return http.request.render('hotel_dashboard.listing', {
#             'root': '/hotel_dashboard/hotel_dashboard',
#             'objects': http.request.env['hotel_dashboard.hotel_dashboard'].search([]),
#         })

#     @http.route('/hotel_dashboard/hotel_dashboard/objects/<model("hotel_dashboard.hotel_dashboard"):obj>', auth='public')
#     def object(self, obj, **kw):
#         return http.request.render('hotel_dashboard.object', {
#             'object': obj
#         })

