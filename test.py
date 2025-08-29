# VERY GENERIC – will only work if the vendor exposes a COM ProgID
import win32com.client

drv = win32com.client.Dispatch("Vendor.FiscalDriver")  # ProgID differs per vendor
drv.Host = "123.123.123.14"
drv.Port = 8123
drv.Password = "krLGfzRh"
drv.OperatorId = 3
drv.OperatorPin = "4321"

# Most drivers have a method to fetch departments/operators or to “Test” connection
print(drv.GetDepartments())  # method name will differ
