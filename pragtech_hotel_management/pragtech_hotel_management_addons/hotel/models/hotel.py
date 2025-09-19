import datetime
import time
# from typing_extensions import Self

from odoo import netsvc
# from odoo.addons import decimal_precision as dp
from odoo import api, fields, models, SUPERUSER_ID, _
from odoo.exceptions import AccessError, UserError, ValidationError
from odoo.tools import float_is_zero, float_compare
from odoo.tools.translate import html_translate
import math
import logging

_logger = logging.getLogger(__name__)


class hotel_floor(models.Model):
    _name = "hotel.floor"
    _description = "Floor"

    name = fields.Char('Floor Name', required=True, index=True)
    sequence = fields.Integer('Sequence')


class product_category(models.Model):
    _inherit = "product.category"

    isroomtype = fields.Boolean('Is Room Type')
    isamenitype = fields.Boolean('Is amenities Type')
    isservicetype = fields.Boolean('Is Service Type')

    company_id = fields.Many2one('res.company', string='Company')

    @api.model_create_multi
    def create(self, vals):
        # for val_list1 in vals:
        #  #   val_list1['company_id']=self.env.user.company_id.id
        res = super(product_category, self).create(vals)
        res.company_id = self.env.user.company_id.id

        return res


class hotel_room_type(models.Model):
    _name = "hotel.room_type"
    _inherits = {'product.category': 'cat_id'}
    _description = "Room Type"

    room_type_amenities = fields.Many2many(
        'hotel.room_amenities', 'temp_tab_type', 'room_type_amenities', 'rcateg_id', 'Room Amenities')
    cat_id = fields.Many2one(
        'product.category', string='Category', required=True, ondelete="cascade")
    description = fields.Html('Description')
    # facilities = fields.Html('Facilities and Services')
    amenities = fields.Html('Amenities')
    services = fields.Html('services')
    img_ids = fields.One2many('hotel.room.images', 'room_images_id', 'Image')
    company_id = fields.Many2one(
        'res.company', string='Company',
        domain="[('id', 'in', [current_company_id])]",
        required=True)
    isroomtype = fields.Boolean(
        'Is Room Type', related='cat_id.isroomtype', inherited=True, default=True)

    @api.onchange('company_id')
    def product_category_company_change(self):
        product_category_id = self.env['product.category'].search([('name', '=', self.name)])
        _logger.info("Product Category===>>>>>>>>>>>>>{}".format(product_category_id))
        product_category_id.write({'company_id': self.company_id})

    @api.model_create_multi
    def create(self, vals):
        res = super(hotel_room_type, self).create(vals)
        return res

    # @api.multi

    def unlink(self):
        for categ in self:
            categ.cat_id.unlink()
        return super(hotel_room_type, self).unlink()


class hotel_room_images(models.Model):
    _name = "hotel.room.images"
    _description = "Store multiple images for each room"

    room_images_id = fields.Many2one('hotel.room_type', 'img_ids')
    name = fields.Char("Title", required=True)
    img = fields.Binary(
        "Image", help="This field holds the image for Room, limited to 1024x1024px")


class product_product(models.Model):
    _inherit = "product.product"

    isroom = fields.Boolean('Is Room')
    iscategid = fields.Boolean('Is categ id')
    isservice = fields.Boolean('Is Service id')
    state = fields.Selection([('', ''),
                              ('draft', 'Available'),
                              ('sellable', 'Booked'),
                              ], 'Status', default='draft', help="Tells the user if room is available of booked.")


class hotel_room_amenities_type(models.Model):
    _name = 'hotel.room_amenities_type'
    _description = 'amenities Type'
    _inherits = {'product.category': 'cat_id'}

    cat_id = fields.Many2one(
        'product.category', string='category', required=True, ondelete="cascade")
    isamenitype = fields.Boolean(
        'Is amenities Type', related='cat_id.isamenitype', inherited=True, default=True)
    company_id = fields.Many2one(
        'res.company', string='Company',
        domain="[('id', 'in', [current_company_id])]",
        required=True)

    # @api.multi
    def unlink(self):
        for categ in self:
            categ.cat_id.unlink()
        return super(hotel_room_amenities_type, self).unlink()


class hotel_room_amenities(models.Model):
    _name = 'hotel.room_amenities'
    _description = 'Room amenities'
    _inherits = {'product.product': 'room_categ_id'}
    _inherit = ['mail.thread']

    room_categ_id = fields.Many2one(
        'product.product', string='product category', required=True, ondelete="cascade")
    rcateg_id = fields.Many2one(
        'hotel.room_amenities_type', 'Amenity Catagory')
    amenity_rate = fields.Integer('Amenity Rate')

    iscategid = fields.Boolean(
        'Is categ id', related='room_categ_id.iscategid', inherited=True, default=True)

    def action_open_documents(self):
        self.room_categ_id.product_tmpl_id.action_open_documents()

    @api.onchange('shop_id')
    def on_change_shop_id(self):
        if not self.shop_id:
            return {'value': {}}
        temp = self.shop_id
        self.company_id = temp.company_id.id

    def action_compute_bom_days(self):
        return True

    def action_open_label_layout(self):
        action = self.env['ir.actions.act_window']._for_xml_id('product.action_open_label_layout')
        action['context'] = {'default_product_tmpl_ids': self.ids}
        return action

    def open_pricelist_rules(self):
        self.ensure_one()
        domain = ['|',
                  ('product_tmpl_id', '=', self.id),
                  ('product_id', 'in', self.product_variant_ids.ids)]
        return {
            'name': ('Price Rules'),
            'view_mode': 'tree,form',
            'views': [(self.env.ref('product.product_pricelist_item_tree_view_from_product').id, 'tree'),
                      (False, 'form')],
            'res_model': 'product.pricelist.item',
            'type': 'ir.actions.act_window',
            'target': 'current',
            'domain': domain,
            'context': {
                'default_product_tmpl_id': self.id,
                'default_applied_on': '1_product',
                'product_without_variants': self.product_variant_count == 1,
            },
        }

    # @api.multi

    def read_followers_data(self, follower_ids):
        result = []
        technical_group = self.env['ir.model.data'].get_object(
            'base', 'group_no_one')
        for follower in self.env['res.partner'].browse(self._ids):
            is_editable = self._uid in map(
                lambda x: x.id, technical_group.users)
            is_uid = self._uid in map(lambda x: x.id, follower.user_ids)
            data = (follower.id,
                    follower.name,
                    {'is_editable': is_editable, 'is_uid': is_uid},
                    )
            result.append(data)
        return result

    @api.onchange('type')
    def onchange_type(self):
        res = {}
        if type in ('consu', 'service'):
            res = {'value': {'valuation': 'manual_periodic'}}
        return res

    @api.onchange('tracking')
    def onchange_tracking(self):
        if not self.tracking:
            return {}
        product_product = self.env['product.product']
        variant_ids = product_product.search(
            [('product_tmpl_id', 'in', self._ids)])
        for variant_id in variant_ids:
            variant_id.onchange_tracking()

    # @api.multi

    def unlink(self):
        for categ in self:
            categ.room_categ_id.unlink()
        return super(hotel_room_amenities, self).unlink()

    def message_get_subscription_data(self, user_pid=None, ):
        """ Wrapper to get subtypes data. """
        return self.env['mail.thread']._get_subscription_data(None, None, user_pid=user_pid, context=self._context)


class product_template(models.Model):
    _inherit = "product.template"

    max_adult = fields.Integer('Max Adult')
    max_child = fields.Integer('Max Child')

class hotel_room(models.Model):
    _name = 'hotel.room'
    _inherits = {'product.product': 'product_id'}
    _description = 'Hotel Room'
    _inherit = ['mail.thread']

    def action_compute_bom_days(self):
        return True

    def action_open_documents(self):
        self.product_id.product_tmpl_id.action_open_documents()

    @api.model_create_multi
    def create(self, vals):
        _logger.info("VALS====>>>>>>>>>>>>>>{}".format(vals))

        return super(hotel_room, self).create(vals)

    def action_open_label_layout(self):
        action = self.env['ir.actions.act_window']._for_xml_id('product.action_open_label_layout')
        action['context'] = {'default_product_tmpl_ids': self.ids}
        return action

    def open_website_url(self):
        self.ensure_one()
        res = self.product_id.product_tmpl_id.open_website_url()
        res['url'] = self.product_id.website_url
        return res

    def open_pricelist_rules(self):
        self.ensure_one()
        domain = ['|',
                  ('product_tmpl_id', '=', self.id),
                  ('product_id', 'in', self.product_variant_ids.ids)]
        return {
            'name': ('Price Rules'),
            'view_mode': 'tree,form',
            'views': [(self.env.ref('product.product_pricelist_item_tree_view_from_product').id, 'tree'),
                      (False, 'form')],
            'res_model': 'product.pricelist.item',
            'type': 'ir.actions.act_window',
            'target': 'current',
            'domain': domain,
            'context': {
                'default_product_tmpl_id': self.id,
                'default_applied_on': '1_product',
                'product_without_variants': self.product_variant_count == 1,
            },
        }

    def action_open_label_layout(self):
        action = self.env['ir.actions.act_window']._for_xml_id('product.action_open_label_layout')
        action['context'] = {'default_product_tmpl_ids': self.ids}
        return action

    # @api.one
    # @api.returns('self', lambda value: value.id if value.id else False)
    # def copy(self, default=None):
    #     context = self._context or {}
    #     default = dict(default or {}, name=("%s (Copy)") % self.name)
    #     context_wo_lang = dict(context or {})
    #     context_wo_lang.pop('lang', None)
    #     context = context_wo_lang
    #     room = self.browse(self.ids)
    #     if context.get('variant'):
    #         # if we copy a variant or create one, we keep the same template
    #         default['product_id'] = room.product_id.id
    #     elif 'name' not in default:
    #         default['name'] = _("%s (copy)") % (room.name,)
    #
    #     print('----------------default------------------')
    #     print(default)
    #     return super(hotel_room, self).copy(default=default)

    @api.onchange('type')
    def onchange_type(self):
        res = {}
        if type in ('consu', 'service'):
            res = {'value': {'valuation': 'manual_periodic'}}
        return res

    @api.onchange('tracking')
    def onchange_tracking(self):
        if not self.tracking:
            return {}
        product_product = self.env['product.product']
        variant_ids = product_product.search(
            [('product_tmpl_id', 'in', self._ids)])
        for variant_id in variant_ids:
            variant_id.onchange_tracking()

    product_id = fields.Many2one(
        'product.product', string='Product_id', required=True, ondelete="cascade")
    floor_id = fields.Many2one('hotel.floor', 'Floor No')
    # max_adult = fields.Integer('Max Adult')
    # max_child = fields.Integer('Max Child')
    room_amenities = fields.Many2many(
        'hotel.room_amenities', 'temp_tab', 'room_amenities', 'rcateg_id', 'Room Amenities')

    isroom = fields.Boolean(
        'Is Hotel Room', related='product_id.isroom', inherited=True, default=True)
    # rental = fields.Boolean(
    #     'Is Rental', related='product_id.rental', inherited=True, default=True)
    rental = fields.Boolean(
        'Is Rental', default=True)
    allow_out_of_stock_order = fields.Boolean(string='Continue selling when out-of-stock', default=True)
    show_availability = fields.Boolean(string='Show availability Qty', default=False)
    available_threshold = fields.Float(string='Show Threshold', default=5.0)
    out_of_stock_message = fields.Html(string="Out-of-Stock Message", translate=html_translate)

    # @api.multi

    def read_followers_data(self):
        result = []
        technical_group = self.env['ir.model.data'].get_object(
            'base', 'group_no_one', context=self._context)
        for follower in self.env['res.partner'].browse(self._ids):
            is_editable = self._uid in map(
                lambda x: x.id, technical_group.users)
            is_uid = self._uid in map(lambda x: x.id, follower.user_ids)
            data = (follower.id,
                    follower.name,
                    {'is_editable': is_editable, 'is_uid': is_uid},
                    )
            result.append(data)
        return result

    def message_get_subscription_data(self, user_pid=None):
        """ Wrapper to get subtypes data. """
        return self.env['mail.thread']._get_subscription_data(None, None, user_pid=user_pid)

    # @api.multi
    def unlink(self):
        for categ in self:
            categ.product_id.unlink()


class hotel_folio(models.Model):

    # @api.one
    @api.returns('self', lambda value: value.id)
    def copy(self, default=None, ):
        context = self._context or {}
        default = dict(default or {}, name=_("%s (Copy)") % self.name)
        context_wo_lang = dict(context or {})
        context_wo_lang.pop('lang', None)
        context = context_wo_lang
        room = self.browse(self._ids)
        if context.get('variant'):
            # if we copy a variant or create one, we keep the same template
            default['order_id'] = room.order_id.id
        elif 'name' not in default:
            default['name'] = _("%s (copy)") % (room.name,)

        return super(hotel_folio, self).copy(default=default)

    # @api.multi

    def button_dummy11(self):
        val = val1 = 0.0
        for order in self:
            for line in order.order_line:
                val1 += line.price_subtotal
                val += self.env['sale.order']._amount_line_tax(line)
        total = val1 + val
        if val:
            self._cr.execute(
                """UPDATE sale_order SET amount_untaxed =%s, amount_tax =%s, amount_total =%s WHERE id =%s""",
                (val1, val, total, order.order_id.id))
        else:
            self._cr.execute(
                """UPDATE sale_order SET amount_untaxed =%s, amount_total =%s WHERE id =%s""",
                (val1, val1, order.order_id.id))
        self._cr.commit()
        return True

    _name = 'hotel.folio'
    _description = 'hotel folio new'
    _inherit = ['mail.thread']
    _inherits = {'sale.order': 'order_id'}
    order_id = fields.Many2one(
        'sale.order', required=True, string='Order Id', ondelete='cascade')
    room_lines = fields.One2many(
        'hotel_folio.line', 'folio_id', string="Rooms")
    service_lines = fields.One2many(
        'hotel_service.line', 'folio_id')
    order_reserve_invoice_ids = fields.Many2many(
        'account.move', 'order_reserve_invoice_rel', 'folio_id', 'invoice_id', 'Order Reservation Invoices',
        readonly=True)
    table_order_invoice_ids = fields.Many2many(
        'account.move', 'table_order_invoice_rel', 'order_id', 'invoice_id', 'Table Order Invoices', readonly=True)
    note = fields.Text(string='Note')
    shop_id = fields.Many2one('sale.shop', 'Hotel', domain="[('company_id', '=', [current_company_id])]",)
    currency_id = fields.Many2one('res.currency', 'Currency', required=True, related='company_id.currency_id',
                                  default=lambda self: self.env.user.company_id.currency_id.id)

    # @api.multi
    def _get_report_base_filename(self):
        return "Room-Guest-WiseReport"

    def action_view_invoice1(self):
        invoices = self.mapped('invoice_ids')
        action = self.env.ref('account.view_invoice_tree').read()[0]
        if len(invoices) > 1:
            action['domain'] = [('id', 'in', invoices.ids)]
        elif len(invoices) == 1:
            form_view = [
                (self.env.ref('account.view_move_line_form').id, 'form')]
            if 'views' in action:
                action['views'] = form_view + \
                                  [(state, view)
                                   for state, view in action['views'] if view != 'form']
            else:
                action['views'] = form_view
            action['res_id'] = invoices.ids[0]
        else:
            action = {'type': 'ir.actions.act_window_close'}
        return action

    def action_view_invoice(self):
        invoices = self.mapped('invoice_ids')
        action = self.env.ref('account.action_move_out_invoice_type').read()[0]
        if len(invoices) > 1:
            action['domain'] = [('id', 'in', invoices.ids)]
        elif len(invoices) == 1:
            form_view = [(self.env.ref('account.view_move_form').id, 'form')]
            if 'views' in action:
                action['views'] = form_view + \
                                  [(state, view)
                                   for state, view in action['views'] if view != 'form']
            else:
                action['views'] = form_view
            action['res_id'] = invoices.id
        else:
            action = {'type': 'ir.actions.act_window_close'}

        # context = {
        #     'default_type': 'out_invoice',
        # }
        context = {}
        if len(self) == 1:
            context.update({
                'default_partner_id': self.partner_id.id,
                'default_partner_shipping_id': self.partner_shipping_id.id,
                'default_invoice_payment_term_id': self.payment_term_id.id or self.partner_id.property_payment_term_id.id or
                                                   self.env['account.move'].default_get(
                                                       ['invoice_payment_term_id']).get('invoice_payment_term_id'),
                'default_invoice_origin': self.mapped('name'),
                'default_user_id': self.user_id.id,
            })
        action['context'] = context
        return action

    @api.model_create_multi
    def create(self, vals):
        for val in vals:
            tmp_room_lines = val.get('room_lines', [])
            tmp_service_lines = val.get('service_lines', [])
            if "folio_id" not in val:
                val.update({'room_lines': [], 'service_lines': []})
                folio_id = super(hotel_folio, self).create(val)
                for line in tmp_room_lines:
                    line[2].update({'folio_id': folio_id})
                for line in tmp_service_lines:
                    line[2].update({'folio_id': folio_id})
                val.update(
                    {'room_lines': tmp_room_lines, 'service_lines': tmp_service_lines})
                super(hotel_folio, self).write(val)

            else:
                folio_id = super(hotel_folio, self).create(val)
        return folio_id


    def action_confirm(self):
        for record in self:
            # record.room_lines.update({
            #     'checkout_date': datetime.datetime.now()
            # })
            for line in record.room_lines:
                room_his_id = self.env['hotel.room.booking.history'].search(
                    [('booking_id', '=', record.reservation_id.id),
                     ('history_id.name', '=', line.product_id.name)])
                if room_his_id:
                    room_his_id.sudo().write({
                        'check_out': line.checkout_date
                    })

        self.write({'state': 'sale'})
        self.order_id.action_confirm()
        return True

    def action_button_confirm(self):
        assert len(
            self._ids) == 1, 'This option should only be used for a single id at a time.'
        wf_service = netsvc.LocalService('workflow')
        wf_service.trg_validate(self.uid, 'hotel.folio',
                                self._ids[0], 'order_confirm', self._cr)

        view_ref = self.env['ir.model.data'].get_object_reference(
            'hotel', 'view_hotel_folio1_form')
        view_id = view_ref and view_ref[1] or False,
        return {
            'type': 'ir.actions.act_window',
            'name': ('Hotel Folio'),
            'res_model': 'hotel.folio',
            'res_id': self.ids[0],
            'view_type': 'form',
            'view_mode': 'form',
            'view_id': view_id,
            'target': 'current',
            'nodestroy': True,
        }

    # @api.onchange('shop_id')
    # def onchange_shop_id(self):
    #     return self.order_id.onchange_shop_id()

    @api.onchange('partner_id')
    def onchange_partner_id(self):
        if self.ids:
            return self.order_id.onchange_partner_id()

    # @api.multi

    def button_dummy(self):
        for record in self:
            return self.env['sale.order'].browse(record.order_id).button_dummy()

    # ====================corrected============================================
    # @api.multi

    def action_invoice_create(self, grouped=False, states=['confirmed', 'done']):
        for record in self._ids:
            i = record.order_id.action_invoice_create(
                grouped=False, states=['confirmed', 'done'])

            for line in self._ids:
                # print ("line", line)
                line.write({'invoiced': True})
                if grouped:
                    line.write({'state': 'progress'})
                else:
                    line.write({'state': 'progress'})
                for obj in line.room_lines:
                    obj.product_id.write({'state': 'draft'})
                if line.order_reserve_invoice_ids:
                    for order_line in line.order_reserve_invoice_ids:
                        if order_line.state == 'draft':
                            raise ValidationError(
                                ('Error !', 'Checkout Table Reservation Invoices are not validated !'))
                if line.table_order_invoice_ids:

                    for table_line in line.table_order_invoice_ids:
                        if table_line.state == 'draft':
                            raise ValidationError(
                                ('Error !', 'Checkout Table Order Invoices are not validated !'))
            return i

    # @api.multi

    def action_invoice_cancel(self):
        for record in self:
            res = record.order_id.action_invoice_cancel()
            for line in record.order_line:
                line.write({'invoiced': False, 'state': 'draft'})
            record.write({'state': 'invoice_except', 'invoice_id': False})
            return res

    # @api.multi

    def action_cancel(self):
        for record in self:
            c = record.order_id.action_cancel()
            for r in self.read(['picking_ids']):
                for pick in r['picking_ids']:
                    wf_service = netsvc.LocalService("workflow")
                    wf_service.trg_validate(
                        'stock.picking', pick, 'button_cancel')
            for r in self.read(['invoice_ids']):
                for inv in r['invoice_ids']:
                    wf_service = netsvc.LocalService("workflow")
                    wf_service.trg_validate(
                        'account.move', inv, 'invoice_cancel')

            record.write({'state': 'cancel'})
            return c

    # @api.multi

    def action_wait(self):
        for o in self:
            if (not o.invoice_ids):
                o.write({'state': 'manual'})
            else:
                o.write({'state': 'progress'})
        return True

    def _message_get_suggested_recipients(self):
        """ Returns suggested recipients for ids. Those are a list of
        tuple (partner_id, partner_name, reason), to be managed by Chatter. """
        result = dict((res_id, []) for res_id in self.ids)
        if 'user_id' in self._fields:
            for obj in self:  # SUPERUSER because of a read on res.users that would crash otherwise
                if not obj.user_id or not obj.user_id.partner_id:
                    continue
                # obj._message_add_suggested_recipient(result, partner=obj.user_id.partner_id, reason=self._fields['user_id'].string)
        return result


class hotel_folio_line(models.Model):
    _name = 'hotel_folio.line'
    _description = 'hotel folio1 room line'
    _inherits = {'sale.order.line': 'order_line_id'}

    order_line_id = fields.Many2one(
        'sale.order.line', string='order_line_id', ondelete='cascade', required=True, )
    folio_id = fields.Many2one(
        'hotel.folio', string='Folio', ondelete='cascade')
    checkin_date = fields.Datetime('Check In')
    checkout_date = fields.Datetime('Check Out')
    categ_id = fields.Many2one(
        'product.category', 'Room Type', domain="[('isroomtype','=',True)]", required=True)

    @api.onchange('product_id')
    def product_id_change(self):
        if self.product_id:
            self.product_uom = self.product_id.uom_id
            product_browse = self.product_id
            pricelist = self.folio_id.pricelist_id.id

            ctx = self._context and self._context.copy() or {}
            ctx.update({'date': self.checkin_date})

            price = self.env['product.pricelist']._price_get(
                self.product_id, self.product_uom_qty,uom=product_browse.uom_id, date=self.checkin_date)[pricelist]

            self.price_unit = price
            self.name = self.product_id.description_sale

    # @api.multi

    @api.model_create_multi
    def create(self, vals):
        for val in vals:
            if not self._context:
                self._context = {}
            if "folio_id" in val:
                folio = self.env["hotel.folio"].browse([val['folio_id']])[0]
                # self.env["product.product"].browse(
                #     vals['product_id']).write({'state': 'sellable'})
                val.update({'order_id': folio.order_id.id})

            roomline = super(hotel_folio_line, self).create(val)

            if roomline:
                cnt2 = 0
                cnt1 = 0
                for lines_k in folio.room_lines:
                    cnt2 = cnt2 + 1
                for lines_k in folio.reservation_id.reservation_line:
                    cnt1 = cnt1 + 1
                if roomline:
                    if cnt2 > cnt1:
                        ff = self.env['hotel.reservation.line'].create(
                            {
                                'checkin': val['checkin_date'],
                                'checkout': val['checkout_date'],
                                'categ_id': val['categ_id'],
                                'room_number': val['product_id'],
                                'line_id': folio.reservation_id.id,
                                'price': val['price_unit'],
                                'discount': val['discount'],

                            }
                        )
                        roomline.write({"hotel_reservation_line_id": ff.id})

        return roomline

    @api.model
    def write(self, vals):
        for line_obj in self:
            line_search = self.env['hotel.reservation.line'].search(
                [('id', '=', line_obj.hotel_reservation_line_id.id)])
            if 'product_id' in vals:
                if line_search.room_number.id != vals['product_id']:
                    room_id_room_data = self.env['hotel.room'].search(
                        [('name', '=', line_search.room_number.name)])
                    for history in room_id_room_data.room_folio_ids:
                        if history.booking_id.id == line_search.line_id.id and line_obj.checkin_date == history.check_in and line_obj.checkout_date == history.check_out:
                            history.unlink()
                            # product_name = self.env['product.product'].search([('id', '=', vals['product_id'])])
                            room_name = self.env['hotel.room'].search(
                                [('product_id', '=', vals['product_id'])])

                            value_history = {

                                'partner_id': line_search.line_id.partner_id.id,
                                'history_id': room_name.id,
                                'booking_id': line_search.line_id.id,
                                'state': 'done',
                                'category_id': room_name.categ_id.id,  # room_line_id.categ_id.id,
                                'name': room_name.name,
                            }
                            if 'check_in' in vals:
                                value_history.update(
                                    {'check_in': vals['check_in']})
                                value_history.update(
                                    {'check_in_date': vals['check_in']})

                            else:
                                value_history.update(
                                    {'check_in': line_obj.checkin_date})
                                value_history.update(
                                    {'check_in_date': line_obj.checkin_date})

                            if 'checkout_date' in vals:
                                value_history.update(
                                    {'check_out': vals['checkout_date']})
                                value_history.update(
                                    {'check_out_date': vals['checkout_date']})

                            else:
                                value_history.update(
                                    {'check_out': line_obj.checkout_date})
                                value_history.update(
                                    {'check_out_date': line_obj.checkout_date})

                            if 'product_id' in vals:
                                value_history.update(
                                    {'product_id': vals['product_id']})

                            else:
                                value_history.update(
                                    {'product_id': line_obj.product_id.id})
                            room_his_id = self.env['hotel.room.booking.history'].create(
                                value_history)

            room_name_K = self.env['hotel.room'].search(
                [('product_id', '=', line_search.room_number.id)])

            for history_k in room_name_K.room_folio_ids:
                if history_k.booking_id.id == line_search.line_id.id and line_obj.checkin_date == history_k.check_in and line_obj.checkout_date == history_k.check_out:

                    if 'checkout_date' in vals:

                        if history_k:
                            history_k.write(
                                {'check_out': vals['checkout_date']})
                            history_k.write(
                                {'check_out_date': vals['checkout_date']})

                    if 'checkin_date' in vals:

                        if history_k:
                            history_k.write({'check_in': vals['checkin_date']})
                            history_k.write(
                                {'check_in_date': vals['checkin_date']})

            if line_search:

                if 'checkout_date' in vals:
                    line_search.write({

                        'checkout': vals['checkout_date']})

                if 'checkin_date' in vals:
                    line_search.write({

                        'checkin': vals['checkin_date']})

                if 'categ_id' in vals:
                    line_search.write({

                        'categ_id': vals['categ_id']})

                if 'product_id' in vals:
                    line_search.write({

                        'room_number': vals['product_id']})

                if 'discount' in vals:
                    line_search.write({
                        'discount': vals['discount']})

                if 'price_unit' in vals:
                    line_search.write({
                        'sub_total1': vals['price_unit'],
                        'price': vals['price_unit']
                    })
                if 'product_uom_qty' in vals:
                    line_search.write({
                        'number_of_days': vals['product_uom_qty']})
                    line_search.count_price()
        
        if not 'price_unit' in vals:
            vals.update({
                'price_unit': line_obj.price_unit
            })
        return super(hotel_folio_line, self).write(vals)

    @api.onchange('checkout_date', 'checkin_date')
    @api.depends('checkin_date', 'checkout_date', 'product_id', 'folio_id.shop_id')
    def on_change_checkout(self):

        product_uom_id = ""
        if self.checkout_date and self.checkin_date > self.checkout_date:
            return {'warning': {'title': "Error", 'message': "Departure date must be greater than Arrival Date"}, }
        if self.checkin_date and self.checkout_date:
            print('---------self: ', self)
            print('---------self.folio_id: ', self.folio_id)
            print('---------self.folio_id.name: ', self.folio_id.name)
            print('---------self.folio_id.shop_id: ', self.folio_id.shop_id)
            policy_obj = self.env['checkout.configuration'].search(
                [('shop_id', '=', self.folio_id.shop_id.id)])
            if not policy_obj:
                raise UserError(
                    'Configuration Error! Checkout policy is not define.')
            check_in = self.checkin_date

            check_out = self.checkout_date

            day_count1 = (check_out - check_in).days
            if not policy_obj.name == '24hour':
                check_in = self.checkin_date

                check_out = self.checkout_date
                _logger.info("DAY COUNT====>>>>%s", check_in)
                _logger.info("DAY COUNT====>>>>%s", check_out)
                day_count1 = check_out - check_in

                day_count2 = day_count1.total_seconds()

                day_count2 = day_count2 / 86400
                day_count2 = "{:.2f}".format(day_count2)
                _logger.info("DIFFERENCE==>>>>>>>>>{}".format(day_count2))
                day_count2 = math.ceil(float(day_count2))

                _logger.info("DAY COUNT22===>>>>>>>>>>>>>>>>{}".format(day_count2))

                day_count1 = day_count2

            else:
                check_in = self.checkin_date
                check_out = self.checkout_date
                _logger.info("CHECK IN ===>>>>>>>>>>>>>>>{}".format(check_in))
                _logger.info("CHECK OUT===>>>>>>>>>>>>{}".format(check_out))

                day_count1 = check_out - check_in

                day_count2 = day_count1.total_seconds()
                day_count2 = day_count2 / 86400
                day_count2 = "{:.2f}".format(day_count2)

                _logger.info("DIFFERENCE==>>>>>>>>>{}".format(day_count2))
                day_count2 = math.ceil(float(day_count2))

                day_count1 = day_count2
            self.product_uom_qty = day_count1 if day_count1 else 1


class hotel_service_line(models.Model):
    _name = 'hotel_service.line'
    _description = 'hotel Service line'
    _inherits = {'sale.order.line': 'service_line_id'}

    service_line_id = fields.Many2one(
        'sale.order.line', string='service_line_id', required=True, ondelete='cascade')
    folio_id = fields.Many2one('hotel.folio', string='Folio', ondelete='cascade')

    # @api.multi
    def unlink(self):
        for categ in self:
            categ.service_line_id.unlink()
        return super(hotel_service_line, self).unlink()

    @api.model_create_multi
    def create(self, vals):
        if not self._context:
            self._context = {}
        for line in vals:
            if line.get("folio_id"):
                folio = self.env["hotel.folio"].browse([line['folio_id']])[0]
                line.update({'order_id': folio.order_id.id})
        roomline = super(hotel_service_line, self).create(vals)
        return roomline

    @api.onchange('folio_id')
    def on_change_checkout(self):
        qty = 1
        for i in self.folio_id.room_lines:
            checkout_date = str(i.checkout_date)
            checkin_date = str(i.checkin_date)
            break
        if checkout_date < checkin_date:
            raise ValidationError(
                'Error !', 'Checkout must be greater or equal checkin date')
        if checkin_date:
            diffDate = datetime.datetime(*time.strptime(checkout_date, '%Y-%m-%d %H:%M:%S')[
                                          :5]) - datetime.datetime(
                *time.strptime(checkin_date, '%Y-%m-%d %H:%M:%S')[:5])
            qty = diffDate.days
        return {'value': {'product_uom_qty': qty}}

    # @api.onchange('product_id')
    # def product_id_change(self):
    #     _logger.info('------------- onchange_product_id: 2')
    #     if self.product_id:
    #         self.product_uom = self.product_id.uom_id
    #         self.price_unit = self.product_id.lst_price
    #         self.name = self.product_id.description_sale


class hotel_service_type(models.Model):
    _name = "hotel.service_type"
    _inherits = {'product.category': 'ser_id'}
    _description = "Service Type"

    ser_id = fields.Many2one('product.category', string='Category',
                             required=True, index=True, ondelete="cascade")
    isservicetype = fields.Boolean(
        'Is Service Type', related='ser_id.isservicetype', inherited=True, default=True)
    company_id = fields.Many2one('res.company', string='Company',
                                 domain="[('id', 'in', [current_company_id])]",
                                 required=True)

    # @api.multi
    def unlink(self):
        for categ in self:
            categ.ser_id.unlink()
        return super(hotel_service_type, self).unlink()


class hotel_services(models.Model):
    _name = 'hotel.services'
    _description = 'Hotel Services and its charges'
    _inherits = {'product.product': 'service_id'}
    _inherit = ['mail.thread']

    service_id = fields.Many2one(
        'product.product', string='Service Id', required=True, ondelete='cascade')
    isservice = fields.Boolean(
        'Is Service', related='service_id.isservice', inherited=True, default=True)

    def action_open_documents(self):
        self.service_id.product_tmpl_id.action_open_documents()

    @api.onchange('shop_id')
    def on_change_shop_id(self):
        if not self.shop_id:
            return {'value': {}}
        temp = self.shop_id
        self.company_id = temp.company_id.id

    def action_compute_bom_days(self):
        return True

    def open_pricelist_rules(self):
        self.ensure_one()
        domain = ['|',
                  ('product_tmpl_id', '=', self.id),
                  ('product_id', 'in', self.product_variant_ids.ids)]
        return {
            'name': ('Price Rules'),
            'view_mode': 'tree,form',
            'views': [(self.env.ref('product.product_pricelist_item_tree_view_from_product').id, 'tree'),
                      (False, 'form')],
            'res_model': 'product.pricelist.item',
            'type': 'ir.actions.act_window',
            'target': 'current',
            'domain': domain,
            'context': {
                'default_product_tmpl_id': self.id,
                'default_applied_on': '1_product',
                'product_without_variants': self.product_variant_count == 1,
            },
        }

    @api.onchange('type')
    def onchange_type(self):
        res = {}
        if self.type in ('consu', 'service'):
            res = {'value': {'valuation': 'manual_periodic'}}
        return res

    @api.onchange('tracking')
    def onchange_tracking(self):
        if not self.tracking:
            return {}
        product_product = self.env['product.product']
        variant_ids = product_product.search(
            [('product_tmpl_id', 'in', self._ids)])
        for variant_id in variant_ids:
            variant_id.onchange_tracking()

    # @api.multi

    def unlink(self):
        for categ in self:
            categ.service_id.unlink()
        return super(hotel_services, self).unlink()

    # @api.multi

    def read_followers_data(self):
        result = []
        technical_group = self.env['ir.model.data'].get_object(
            'base', 'group_no_one', context=self._context)
        for follower in self.env['res.partner'].browse(self._ids):
            is_editable = self.uid in map(
                lambda x: x.id, technical_group.users)
            is_uid = self.uid in map(lambda x: x.id, follower.user_ids)
            data = (follower.id,
                    follower.name,
                    {'is_editable': is_editable, 'is_uid': is_uid},
                    )
            result.append(data)
        return result

    def message_get_subscription_data(self, user_pid=None):
        """ Wrapper to get subtypes data. """
        return self.env['mail.thread']._get_subscription_data(None, None, user_pid=user_pid)

    def action_open_label_layout(self):
        action = self.env['ir.actions.act_window']._for_xml_id('product.action_open_label_layout')
        action['context'] = {'default_product_tmpl_ids': self.ids}
        return action


class sale_order_line(models.Model):
    _inherit = 'sale.order.line'
    _description = 'Inherit Order Line'

    product_uom_qty = fields.Float(
        'Quantity', default=1.00, digits='Product Unit of Measure', required=True)

    @api.model
    def write(self, values):
        if 'display_type' in values and self.filtered(lambda line: line.display_type != values.get('display_type')):
            raise UserError(
                _("You cannot change the type of a sale order line. Instead you should delete the current line and create a new line of the proper type."))

        if 'product_uom_qty' in values:
            precision = self.env['decimal.precision'].precision_get(
                'Product Unit of Measure')
            self.filtered(
                lambda r: r.state == 'sale' and float_compare(r.product_uom_qty, values['product_uom_qty'],
                                                              precision_digits=precision) != 0)._update_line_quantity(
                values)

        # Prevent writing on a locked SO.
        protected_fields = self._get_protected_fields()
        
        res = super(sale_order_line, self).write(values)

        return res
