

from odoo import models, fields, api


class Hotel_dashboard(models.Model):
    _inherit = 'hotel.reservation'



    checkin = fields.Datetime(related='reservation_line.checkin',store=True)
    checkout = fields.Datetime(related='reservation_line.checkout',store=True)
    room_type = fields.Char(related='reservation_line.categ_id.name',string="Room Type",store=True)
    room_no = fields.Many2many('product.product',string="Room Number")
    status = fields.Selection([('booking','Booking'),('cancelled','Cancelled'),('confirmed', 'Confirmed'),('checkin','Check in'),('checkout','Check out')],string="Room status",default='booking')

    @api.model
    def create(self,vals):
        res=super(Hotel_dashboard, self).create(vals)
        for l in res.reservation_line:
            res.room_no = [(4, l.room_number.id)]
        return res

    @api.model
    def get_data(self):
        # print('*******************',self.shop_id)
        shop_id = self.env['sale.shop'].search([],limit=1).id
        if shop_id:
            check_in = self.env['hotel.folio'].search([('state', '=', 'draft'), ('shop_id', '=', int(shop_id))])
            check_out = self.env['hotel.folio'].search([('state', '=', 'check_out'), ('shop_id', '=', int(shop_id))])
            total = self.env['hotel.folio'].search([('shop_id', '=', int(shop_id))])
            booked = self.env['hotel.folio'].search([('state', '!=', 'check_out'),('state', '!=', 'done'), ('shop_id', '=', int(shop_id))])
            domain = []
            # cal =self.env['calendar.event'].search([('id','=',1)])
            # print('@@@@@@@@@@@@@@@@@cal@@@@@@@@@@@@@@@@@@@@',cal)
            return {
                'check_in': len(check_in),
                'check_out': len(check_out),
                'total': len(total),
                'booked': len(booked),
            }
        else:
            return {
                'check_in': '',
                'check_out': '',
                'total': '',
                'booked': '',
            }
        

    

