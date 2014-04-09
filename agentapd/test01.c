/*
 * Simu hostapd to call driver_nl80211
 * Copyright (c) 2013-2014, SSE@USTCSZ mengning <mengning@ustc.edu.cn>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include<stdio.h> 			/* perror */
#include<stdlib.h>			/* exit	*/
#include<sys/types.h>		/* WNOHANG */
#include<sys/wait.h>		/* waitpid */
#include<string.h>			/* memset */

#include<arpa/inet.h> /* internet socket */
#include<assert.h>

#define PORT    5001
#define IP_ADDR "127.0.0.1"
#define MAX_CONNECT_QUEUE   1024

#include "driver.h"
#include "wiflow_protocol.h"

struct hostapd_data
{
    struct i802_bss * bss;
};

extern struct wpa_driver_ops *wpa_drivers[];
struct wpa_driver_ap_params *my_params;
struct wpa_driver_capa *my_capa;
struct hostapd_freq_params *my_freq;
char *my_country = ;

int create_allmydata()
{
	my_params = (struct wpa_driver_ap_params *)malloc(sizeof(wpa_driver_ap_params));

	unsigned char *head = {};
	unsigned char *tail = {};
	unsigned char *basic_rates = {};
	unsigned char *ssid = "mengning";
/*	struct wpabuf wpabuf_obj[3];
	wpabuf_obj[0].flags = ;
	wpabuf_obj[0].size = ;
	wpabuf_obj[0].used = ;
	wpabuf_obj[0].buf = ;
	wpabuf_obj[1].flags = ;
	wpabuf_obj[1].size = ;
	wpabuf_obj[1].used = ;
	wpabuf_obj[1].buf = ;
	wpabuf_obj[2].flags = ;
	wpabuf_obj[2].size = ;
	wpabuf_obj[2].used = ;
	wpabuf_obj[2].buf = ;
*/
	/*construct my_params*/
	my_params->head_len = 59;
	my_params->head = malloc(my_params->head_len);
	my_params->tail_len = 55;
	my_params->tail = malloc(my_params->tail_len);
	my_params->dtim_period = 1;
	my_params->beacon_int = 100;
	my_params->basic_rates = malloc();
	my_params->proberesp_len = 0;
	my_params->proberesp = NULL;
	my_params->ssid_len = 8;
	my_params->ssid = malloc(my_params->ssid_len);
	memcpy(ap_params->ssid, ssid, my_params->ssid_len);
	my_params->hide_ssid = 0;
	my_params->pairwise_ciphers = 16;
	my_params->group_cipher = 8;
	my_params->key_mgmt_suites = 2;
	my_params->auth_algs = 3;
	my_params->wpa_version = 3;
	my_params->privacy = 1;
	my_params->beacon_ies = NULL;
	my_params->proberesp_ies = NULL;
	my_params->assocresp_ies = NULL;
	my_params->isolate = 0;
	my_params->cts_protect = 0;
	my_params->preamble = 0;
	my_params->short_slot_time = 1;
	my_params->ht_opmode = -1;
	my_params->interworking = 0;
	my_params->hessid = NULL;
	my_params->access_network_type = ;
	my_params->ap_max_inactivity = 300;
	my_params->disable_dgaf = 0;

	/*construct my_capa*/
	my_capa->auth = 1;
	my_capa->enc = 1;
	my_capa->flags = 1;
	my_capa->key_mgmt = 1;
	my_capa->max_match_sets = 1;
	my_capa->max_remain_on_chan = 1;
	my_capa->max_scan_ssids = 1;
	my_capa->max_stations = 1;
	my_capa->max_sched_scan_ssids = 1;
	my_capa->probe_resp_offloads = 1;
	my_capa->sched_scan_supported = 1;

	/*construct my_freq*/
	my_freq->channel = ;
	my_freq->freq = ;
	my_freq->ht_enabled = ;
	my_freq->mode = ;
	my_freq->sec_channel_offset = ;

	return 0;
}
int main() 
{
    int i = 0;
    void * global_priv;
    unsigned char bssid[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
    unsigned char own_addr[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
    char iface[IFNAMSIZ + 1]  = "wlan1";;
	char bridge[IFNAMSIZ + 1] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
    struct hostapd_data hapd;
    struct wpa_init_params params;
	if (eloop_init()) 
	{
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		return -1;
	}
    /* init nl80211 */ 
	for (i = 0; wpa_drivers[i]; i++) 
	{
		if (wpa_drivers[i]->global_init) 
		{
			global_priv = wpa_drivers[i]->global_init();
			if (global_priv == NULL) {
				printf("global_init Failed to initialize\n");
				return -1;
			}
		}
/*  init params in hostapd(main.c)
    params.global_priv = global.drv_priv[i];
	params.bssid = b;
	params.ifname = hapd->conf->iface;
	params.ssid = hapd->conf->ssid.ssid;
	params.ssid_len = hapd->conf->ssid.ssid_len;
	params.test_socket = hapd->conf->test_socket;
	params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = os_calloc(hapd->iface->num_bss, sizeof(char *));
	if (params.bridge == NULL)
		return -1;
	for (i = 0; i < hapd->iface->num_bss; i++) {
		struct hostapd_data *bss = hapd->iface->bss[i];
		if (bss->conf->bridge[0])
			params.bridge[i] = bss->conf->bridge;
	}

	params.own_addr = hapd->own_addr;
*/
		params.global_priv = global_priv; 
		params.bssid = bssid;
		params.ifname = iface;
		params.ssid = "mengning";
		params.ssid_len = 8;       
        params.test_socket = NULL;
        params.use_pae_group_addr = 0;
        params.num_bridge = 1;
        params.bridge = os_calloc(params.num_bridge, sizeof(char *));
    	if (params.bridge == NULL)
    		return -1;
    	/*params.bridge[0] = bridge;*/

        params.own_addr = own_addr;
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bssid",params.bssid, ETH_ALEN);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ifname:%s",params.ifname);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid:%s",params.ssid);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid_len:%d",params.ssid_len);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->num_bridge:%d",params.num_bridge);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bridge[0]:%s",params.bridge[0],IFNAMSIZ + 1);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->own_addr",params.own_addr, ETH_ALEN);

        assert((wpa_drivers[i]->hapd_init != NULL));
		if (wpa_drivers[i]->hapd_init) 
		{
		    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_init(&hapd,&params)");
			hapd.bss = wpa_drivers[i]->hapd_init(&hapd,&params);
			if (hapd.bss == NULL) 
			{
				printf("hapd_init Failed to initialize\n");
				return -1;
			}		    
		}
        wpa_printf(MSG_DEBUG, "nl80211ext: hapd.bss->ifname:%s",hapd.bss->ifname);
    
	}
	printf("NL80211 initialized\n");

	struct wpa_driver_capa capa;
	int ret;
	ret = wpa_drivers[i]->get_capa(hapd.bss,&capa);

	u16 flags, num_modes;
	struct hostapd_hw_modes *modes;
	modes = wpa_drivers[i]->get_hw_feature_data(hapd.bss, &num_modes,&flags);

/*
	wpa_drivers[i]->set_freq(void *priv, struct hostapd_freq_params *freq);

	int rts = 2347;
	wpa_drivers[i]->set_rts(hapd.bss,rts);
	
	int frag = 2346;
	wpa_drivers[i]->set_frag(hapd.bss, frag);

	wpa_drivers[i]->flush(hapd.bss);

	wpa_drivers[i]->sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,int reason);
	wpa_drivers[i]->send_mlme(void *priv, const u8 *data,
					size_t data_len, int noack);
	wpa_drivers[i]->set_key(const char *ifname, void *priv,
				      enum wpa_alg alg, const u8 *addr,
				      int key_idx, int set_tx,
				      const u8 *seq, size_t seq_len,
				      const u8 *key, size_t key_len);
	wpa_drivers[i]->set_key();
	wpa_drivers[i]->set_key();			    
	wpa_drivers[i]->set_key();
	wpa_drivers[i]->set_ap(void *priv,
				     struct wpa_driver_ap_params *params);
	wpa_drivers[i]->set_key();
	wpa_drivers[i]->set_operstate(void *priv, int state);
	wpa_drivers[i]->set_tx_queue_params(void *priv, int queue, int aifs,
				    int cw_min, int cw_max, int burst_time);
	wpa_drivers[i]->set_tx_queue_params();
	wpa_drivers[i]->set_tx_queue_params();
	wpa_drivers[i]->set_tx_queue_params();

	wpa_drivers[i]->send_mlme(void *priv, const u8 *data,
					size_t data_len, int noack);
*/
	eloop_run();
    return 0;
}

void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
			  union wpa_event_data *data)
{
    printf("wpa_supplicant_event\n");
    return;
}

void wpa_scan_results_free(struct wpa_scan_results *res)
{
    return;   
}


