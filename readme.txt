调整driver调用过程
合理验证
set_key 调用处：
ap_drv_ops.c line 578
ap_drv_ops.c line 578
ap_drv_ops.c line 578
ap_drv_ops.c line 578
Using interface wlan1 with hwaddr 20:4e:7f:da:23:6c and ssid "mengning"
wpa_auth_glue.c line 515
wpa_auth.c line 107
ap_drv_ops.c line 578


下一步还要继续向上找,hostapd_drv_set_key到底是在哪里被调用的，获得set_key参数(over)
set_ap(over)
set_tx_queue_params(over)
queue = 0
aifs = 1
cw_min = 3
cw_max = 7
burst_time = 15

queue = 1
aifs = 1
cw_min = 7
cw_max = 15
burst_time = 30

queue = 2
aifs = 3
cw_min = 15
cw_max = 63
burst_time = 0

queue = 3
aifs = 7
cw_min = 15
cw_max = 1023
burst_time = 0

wpa_supplicant_event();
Using interface wlan1 with hwaddr 20:4e:7f:da:23:6c and ssid "mengning"

EVENT_TX_STATUS
WLAN_FC_TYPE_MGMT:
EVENT_RX_MGMT
EVENT_RX_MGMT
EVENT_RX_MGMT
EVENT_RX_MGMT
EVENT_RX_MGMT
EVENT_RX_MGMT

在原版hostapd ：
global run之前停滞 没有发现网络
hold on before EVENT_TX_STATUS 没有发现网络
hold on before EVENT_RX_MGMT 发现网络

Test 可以接发beacon 可以被Station发现












