cloudap
=======

AP Manager in Cloud,AP Hardware on your side.

### remoteapd

Based on hostapd 2.0,AP Manager in Cloud

* cloudap/remoteapd$ make
* cloudap/remoteapd$ sudo ./hostapd /etc/hostapd.conf (�����ļ���ʹ�õ�driver��nl80211extŶ)

### agentapd

Based on driver_nl80211.c and the related,AP Hardware on your side.

* cloudap/agentapd$ source build.env (���������Ҫִ��dos2unix build.env)
* cloudap/agentapd$ make
* cloudap/agentapd$ ./agentapd


