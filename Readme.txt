hostapd.txt中是直到可以正常发射信号时，
标准的hostapd调用driver_nl80211中函数的过程。
格式：nl80211ext:	#nl80211: XXXXX_XXXXXX 代表这个函数已经在driver_nl80211ext中实现；
剔除了冗余的提示信息，只保留少部分的关键提示；

个人分析：
对比现阶段运行情况，目前判断程序失效的原因可能：

发现get_capa漏填，进行补充

wpa_driver_nl80211_get_hw_feature_data这个函数在修改过后

还是不能正确实现，现阶段尝试的暴力方法貌似不能实现效果；

程序运行接收情况不稳定，不排除架构的细节问题；

重复运行会出type乱码 怀疑对应buffer没有及时清空等。

WIFLOW_NL80211_GET_SCAN_RESULTS2_REQUEST中的2是不是多余了




To Do:
wpa_driver_nl80211_get_capa填充。（over）

wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );\int buf_size = 0;
int ret = 0;
    /* format  type to buf */
    buf_size = MAX_BUF_LEN;
    ret = wiflow_pdu_format(buf,&buf_size, WIFLOW_INIT_CAPA_REQUEST);
if(ret < 0 || buf_size <= 0)
    {
        fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
    }
ret = send(agentfd,buf,buf_size,0);
if(ret < 0)
    {
        fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    }
return 0;

wpa_send_action_format中的type应该为WIFLOW_NL80211_SEND_ACTION_REQUEST（over）

