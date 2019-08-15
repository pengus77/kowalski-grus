/*
 * Copyright (c) 2013-2018 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 *  DOC:    wma_features.c
 *  This file contains different features related functions like WoW,
 *  Offloads, TDLS etc.
 */

/* Header files */

#include "cds_ieee80211_common.h"	/* ieee80211_frame */
#include "wma.h"
#include "wma_api.h"
#include "cds_api.h"
#include "wmi_unified_api.h"
#include "wlan_qct_sys.h"
#include "wni_api.h"
#include "ani_global.h"
#include "wmi_unified.h"
#include "wni_cfg.h"
#include "cfg_api.h"
#include <cdp_txrx_tx_delay.h>
#include <cdp_txrx_peer_ops.h>

#include "qdf_nbuf.h"
#include "qdf_types.h"
#include "qdf_mem.h"
#include "qdf_util.h"

#include "wma_types.h"
#include "lim_api.h"
#include "lim_session_utils.h"

#include "cds_utils.h"

#if !defined(REMOVE_PKT_LOG)
#include "pktlog_ac.h"
#endif /* REMOVE_PKT_LOG */

#include "dbglog_host.h"
#include "csr_api.h"
#include "ol_fw.h"

#include "wma_internal.h"
#include "wma_nan_datapath.h"
#include <cdp_txrx_handle.h>
#include "wlan_pmo_ucfg_api.h"
#include <target_if_scan.h>
#include "wlan_reg_services_api.h"
#include "wlan_roam_debug.h"
#include <wlan_cp_stats_mc_ucfg_api.h>

#ifndef ARRAY_LENGTH
#define ARRAY_LENGTH(a)         (sizeof(a) / sizeof((a)[0]))
#endif

/**
 * WMA_SET_VDEV_IE_SOURCE_HOST - Flag to identify the source of VDEV SET IE
 * command. The value is 0x0 for the VDEV SET IE WMI commands from mobile
 * MCL platform.
 */
#define WMA_SET_VDEV_IE_SOURCE_HOST 0x0
#define WMI_TLV_HEADER_MASK		0xFFFF0000



#if defined(FEATURE_WLAN_DIAG_SUPPORT)
/**
 * qdf_wma_wow_wakeup_stats_event()- send wow wakeup stats
 * @tp_wma_handle wma: WOW wakeup packet counter
 *
 * This function sends wow wakeup stats diag event
 *
 * Return: void.
 */
#ifdef QCA_SUPPORT_CP_STATS
static inline void qdf_wma_wow_wakeup_stats_event(tp_wma_handle wma)
{
	QDF_STATUS status;
	struct wake_lock_stats stats = {0};

	WLAN_HOST_DIAG_EVENT_DEF(wow_stats,
	struct host_event_wlan_powersave_wow_stats);

	status = ucfg_mc_cp_stats_get_psoc_wake_lock_stats(wma->psoc, &stats);
	if (QDF_IS_STATUS_ERROR(status))
		return;
	qdf_mem_zero(&wow_stats, sizeof(wow_stats));

	wow_stats.wow_bcast_wake_up_count = stats.bcast_wake_up_count;
	wow_stats.wow_ipv4_mcast_wake_up_count = stats.ipv4_mcast_wake_up_count;
	wow_stats.wow_ipv6_mcast_wake_up_count = stats.ipv6_mcast_wake_up_count;
	wow_stats.wow_ipv6_mcast_ra_stats = stats.ipv6_mcast_ra_stats;
	wow_stats.wow_ipv6_mcast_ns_stats = stats.ipv6_mcast_ns_stats;
	wow_stats.wow_ipv6_mcast_na_stats = stats.ipv6_mcast_na_stats;
	wow_stats.wow_pno_match_wake_up_count = stats.pno_match_wake_up_count;
	wow_stats.wow_pno_complete_wake_up_count =
				stats.pno_complete_wake_up_count;
	wow_stats.wow_gscan_wake_up_count = stats.gscan_wake_up_count;
	wow_stats.wow_low_rssi_wake_up_count = stats.low_rssi_wake_up_count;
	wow_stats.wow_rssi_breach_wake_up_count =
				stats.rssi_breach_wake_up_count;
	wow_stats.wow_icmpv4_count = stats.icmpv4_count;
	wow_stats.wow_icmpv6_count = stats.icmpv6_count;
	wow_stats.wow_oem_response_wake_up_count =
				stats.oem_response_wake_up_count;

	WLAN_HOST_DIAG_EVENT_REPORT(&wow_stats, EVENT_WLAN_POWERSAVE_WOW_STATS);
}
#else /* QCA_SUPPORT_CP_STATS*/
static inline void qdf_wma_wow_wakeup_stats_event(tp_wma_handle wma)
{
	QDF_STATUS status;
	struct sir_wake_lock_stats stats;

	WLAN_HOST_DIAG_EVENT_DEF(WowStats,
	struct host_event_wlan_powersave_wow_stats);

	status = wma_get_wakelock_stats(&stats);
	if (QDF_IS_STATUS_ERROR(status))
		return;
	qdf_mem_zero(&WowStats, sizeof(WowStats));

	WowStats.wow_bcast_wake_up_count =
		stats.wow_bcast_wake_up_count;
	WowStats.wow_ipv4_mcast_wake_up_count =
		stats.wow_ipv4_mcast_wake_up_count;
	WowStats.wow_ipv6_mcast_wake_up_count =
		stats.wow_ipv6_mcast_wake_up_count;
	WowStats.wow_ipv6_mcast_ra_stats =
		stats.wow_ipv6_mcast_ra_stats;
	WowStats.wow_ipv6_mcast_ns_stats =
		stats.wow_ipv6_mcast_ns_stats;
	WowStats.wow_ipv6_mcast_na_stats =
		stats.wow_ipv6_mcast_na_stats;
	WowStats.wow_pno_match_wake_up_count =
		stats.wow_pno_match_wake_up_count;
	WowStats.wow_pno_complete_wake_up_count =
		stats.wow_pno_complete_wake_up_count;
	WowStats.wow_gscan_wake_up_count =
		stats.wow_gscan_wake_up_count;
	WowStats.wow_low_rssi_wake_up_count =
		stats.wow_low_rssi_wake_up_count;
	WowStats.wow_rssi_breach_wake_up_count =
		stats.wow_rssi_breach_wake_up_count;
	WowStats.wow_icmpv4_count =
		stats.wow_icmpv4_count;
	WowStats.wow_icmpv6_count =
		stats.wow_icmpv6_count;
	WowStats.wow_oem_response_wake_up_count =
		stats.wow_oem_response_wake_up_count;

	WLAN_HOST_DIAG_EVENT_REPORT(&WowStats, EVENT_WLAN_POWERSAVE_WOW_STATS);
}
#endif /* QCA_SUPPORT_CP_STATS */
#else
static inline void qdf_wma_wow_wakeup_stats_event(tp_wma_handle wma)
{
	return;
}
#endif

#ifdef FEATURE_WLAN_DIAG_SUPPORT
/**
 * qdf_wma_wow_wakeup_stats_event()- send wow wakeup stats
 *
 * This function sends wow wakeup stats diag event
 *
 * Return: void.
 */
static void qdf_wma_wow_wakeup_stats_event(void)
{
	QDF_STATUS status;
	struct sir_wake_lock_stats stats;

	WLAN_HOST_DIAG_EVENT_DEF(WowStats,
		struct host_event_wlan_powersave_wow_stats);

	status = wma_get_wakelock_stats(&stats);
	if (QDF_IS_STATUS_ERROR(status))
		return;
	qdf_mem_zero(&WowStats, sizeof(WowStats));
	WowStats.wow_bcast_wake_up_count =
		stats.wow_bcast_wake_up_count;
	WowStats.wow_ipv4_mcast_wake_up_count =
		stats.wow_ipv4_mcast_wake_up_count;
	WowStats.wow_ipv6_mcast_wake_up_count =
		stats.wow_ipv6_mcast_wake_up_count;
	WowStats.wow_ipv6_mcast_ra_stats =
		stats.wow_ipv6_mcast_ra_stats;
	WowStats.wow_ipv6_mcast_ns_stats =
		stats.wow_ipv6_mcast_ns_stats;
	WowStats.wow_ipv6_mcast_na_stats =
		stats.wow_ipv6_mcast_na_stats;
	WowStats.wow_pno_match_wake_up_count =
		stats.wow_pno_match_wake_up_count;
	WowStats.wow_pno_complete_wake_up_count =
		stats.wow_pno_complete_wake_up_count;
	WowStats.wow_gscan_wake_up_count =
		stats.wow_gscan_wake_up_count;
	WowStats.wow_low_rssi_wake_up_count =
		stats.wow_low_rssi_wake_up_count;
	WowStats.wow_rssi_breach_wake_up_count =
		stats.wow_rssi_breach_wake_up_count;
	WowStats.wow_icmpv4_count =
		stats.wow_icmpv4_count;
	WowStats.wow_icmpv6_count =
		stats.wow_icmpv6_count;
	WowStats.wow_oem_response_wake_up_count =
		stats.wow_oem_response_wake_up_count;

	WLAN_HOST_DIAG_EVENT_REPORT(&WowStats, EVENT_WLAN_POWERSAVE_WOW_STATS);
}
#else
static void qdf_wma_wow_wakeup_stats_event(void)
{
}
#endif

#ifdef FEATURE_WLAN_AUTO_SHUTDOWN
/**
 * wma_post_auto_shutdown_msg() - to post auto shutdown event to sme
 *
 * Return: 0 for success or error code
 */
static int wma_wake_reason_auto_shutdown(void)
{
	tSirAutoShutdownEvtParams *auto_sh_evt;
	QDF_STATUS qdf_status;
	struct scheduler_msg sme_msg = { 0 };

	auto_sh_evt = (tSirAutoShutdownEvtParams *)
		      qdf_mem_malloc(sizeof(tSirAutoShutdownEvtParams));
	if (!auto_sh_evt) {
		WMA_LOGE(FL("No Mem"));
		return -ENOMEM;
	}

	auto_sh_evt->shutdown_reason =
		WMI_HOST_AUTO_SHUTDOWN_REASON_TIMER_EXPIRY;
	sme_msg.type = eWNI_SME_AUTO_SHUTDOWN_IND;
	sme_msg.bodyptr = auto_sh_evt;
	sme_msg.bodyval = 0;

	qdf_status = scheduler_post_message(QDF_MODULE_ID_WMA,
					    QDF_MODULE_ID_SME,
					    QDF_MODULE_ID_SME, &sme_msg);
	if (!QDF_IS_STATUS_SUCCESS(qdf_status)) {
		WMA_LOGE("Fail to post eWNI_SME_AUTO_SHUTDOWN_IND msg to SME");
		qdf_mem_free(auto_sh_evt);
		return -EINVAL;
	}

	return 0;
}
#else
static inline int wma_wake_reason_auto_shutdown(void)
{
	return 0;
}
#endif /* FEATURE_WLAN_AUTO_SHUTDOWN */

#ifdef FEATURE_WLAN_SCAN_PNO
static int wma_wake_reason_nlod(t_wma_handle *wma, uint8_t vdev_id)
{
	wmi_nlo_event nlo_event = { .vdev_id = vdev_id };
	WMI_NLO_MATCH_EVENTID_param_tlvs param = { .fixed_param = &nlo_event };

	return target_if_nlo_match_event_handler(wma, (uint8_t *)&param,
						 sizeof(param));
}
#else
static inline int wma_wake_reason_nlod(uint8_t vdev_id)
{
	return 0;
}
#endif /* FEATURE_WLAN_SCAN_PNO */

/**
 * wma_send_snr_request() - send request to fw to get RSSI stats
 * @wma_handle: wma handle
 * @pGetRssiReq: get RSSI request
 *
 * Return: QDF status
 */
QDF_STATUS wma_send_snr_request(tp_wma_handle wma_handle,
				void *pGetRssiReq)
{
	tAniGetRssiReq *pRssiBkUp = NULL;

	/* command is in progress */
	if (NULL != wma_handle->pGetRssiReq)
		return QDF_STATUS_SUCCESS;

	/* create a copy of csrRssiCallback to send rssi value
	 * after wmi event
	 */
	if (pGetRssiReq) {
		pRssiBkUp = qdf_mem_malloc(sizeof(tAniGetRssiReq));
		if (!pRssiBkUp) {
			WMA_LOGE("Failed to alloc memory for tAniGetRssiReq");
			wma_handle->pGetRssiReq = NULL;
			return QDF_STATUS_E_NOMEM;
		}
		pRssiBkUp->sessionId =
			((tAniGetRssiReq *) pGetRssiReq)->sessionId;
		pRssiBkUp->rssiCallback =
			((tAniGetRssiReq *) pGetRssiReq)->rssiCallback;
		pRssiBkUp->pDevContext =
			((tAniGetRssiReq *) pGetRssiReq)->pDevContext;
		wma_handle->pGetRssiReq = (void *)pRssiBkUp;
	}

	if (wmi_unified_snr_request_cmd(wma_handle->wmi_handle)) {
		WMA_LOGE("Failed to send host stats request to fw");
		qdf_mem_free(pRssiBkUp);
		wma_handle->pGetRssiReq = NULL;
		return QDF_STATUS_E_FAILURE;
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_get_snr() - get RSSI from fw
 * @psnr_req: request params
 *
 * Return: QDF status
 */
QDF_STATUS wma_get_snr(tAniGetSnrReq *psnr_req)
{
	tAniGetSnrReq *psnr_req_bkp;
	tp_wma_handle wma_handle = NULL;
	struct wma_txrx_node *intr;

	wma_handle = cds_get_context(QDF_MODULE_ID_WMA);

	if (NULL == wma_handle) {
		WMA_LOGE("%s : Failed to get wma_handle", __func__);
		return QDF_STATUS_E_FAULT;
	}

	intr = &wma_handle->interfaces[psnr_req->sessionId];
	/* command is in progress */
	if (NULL != intr->psnr_req) {
		WMA_LOGE("%s : previous snr request is pending", __func__);
		return QDF_STATUS_SUCCESS;
	}

	psnr_req_bkp = qdf_mem_malloc(sizeof(tAniGetSnrReq));
	if (!psnr_req_bkp) {
		WMA_LOGE("Failed to allocate memory for tAniGetSnrReq");
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_zero(psnr_req_bkp, sizeof(tAniGetSnrReq));
	psnr_req_bkp->staId = psnr_req->staId;
	psnr_req_bkp->pDevContext = psnr_req->pDevContext;
	psnr_req_bkp->snrCallback = psnr_req->snrCallback;
	intr->psnr_req = (void *)psnr_req_bkp;

	if (wmi_unified_snr_cmd(wma_handle->wmi_handle,
				 psnr_req->sessionId)) {
		WMA_LOGE("Failed to send host stats request to fw");
		qdf_mem_free(psnr_req_bkp);
		intr->psnr_req = NULL;
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_process_link_status_req() - process link status request from UMAC
 * @wma: wma handle
 * @pGetLinkStatus: get link params
 *
 * Return: none
 */
void wma_process_link_status_req(tp_wma_handle wma,
				 tAniGetLinkStatus *pGetLinkStatus)
{
	struct link_status_params cmd = {0};
	struct wma_txrx_node *iface =
		&wma->interfaces[pGetLinkStatus->sessionId];

	if (iface->plink_status_req) {
		WMA_LOGE("%s:previous link status request is pending,deleting the new request",
			__func__);
		qdf_mem_free(pGetLinkStatus);
		return;
	}

	iface->plink_status_req = pGetLinkStatus;
	cmd.session_id = pGetLinkStatus->sessionId;
	if (wmi_unified_link_status_req_cmd(wma->wmi_handle, &cmd)) {
		WMA_LOGE("Failed to send WMI link  status request to fw");
		iface->plink_status_req = NULL;
		goto end;
	}

	return;

end:
	wma_post_link_status(pGetLinkStatus, LINK_STATUS_LEGACY);
}

#ifdef WLAN_FEATURE_TSF
/**
 * wma_vdev_tsf_handler() - handle tsf event indicated by FW
 * @handle: wma context
 * @data: event buffer
 * @data len: length of event buffer
 *
 * Return: 0 on success
 */
int wma_vdev_tsf_handler(void *handle, uint8_t *data, uint32_t data_len)
{
	struct scheduler_msg tsf_msg = {0};
	WMI_VDEV_TSF_REPORT_EVENTID_param_tlvs *param_buf;
	wmi_vdev_tsf_report_event_fixed_param *tsf_event;
	struct stsf *ptsf;

	if (data == NULL) {
		WMA_LOGE("%s: invalid pointer", __func__);
		return -EINVAL;
	}
	ptsf = qdf_mem_malloc(sizeof(*ptsf));
	if (NULL == ptsf) {
		WMA_LOGE("%s: failed to allocate tsf data structure", __func__);
		return -ENOMEM;
	}

	param_buf = (WMI_VDEV_TSF_REPORT_EVENTID_param_tlvs *)data;
	tsf_event = param_buf->fixed_param;

	ptsf->vdev_id = tsf_event->vdev_id;
	ptsf->tsf_low = tsf_event->tsf_low;
	ptsf->tsf_high = tsf_event->tsf_high;
	ptsf->soc_timer_low = tsf_event->qtimer_low;
	ptsf->soc_timer_high = tsf_event->qtimer_high;
	ptsf->global_tsf_low = tsf_event->wlan_global_tsf_low;
	ptsf->global_tsf_high = tsf_event->wlan_global_tsf_high;
	WMA_LOGD("%s: receive WMI_VDEV_TSF_REPORT_EVENTID ", __func__);
	WMA_LOGD("%s: vdev_id = %u,tsf_low =%u, tsf_high = %u", __func__,
	ptsf->vdev_id, ptsf->tsf_low, ptsf->tsf_high);

	WMA_LOGD("%s,g_tsf: %d %d; soc_timer: %d %d",
		 __func__, ptsf->global_tsf_low, ptsf->global_tsf_high,
		 ptsf->soc_timer_low, ptsf->soc_timer_high);
	tsf_msg.type = eWNI_SME_TSF_EVENT;
	tsf_msg.bodyptr = ptsf;
	tsf_msg.bodyval = 0;

	if (QDF_STATUS_SUCCESS !=
		scheduler_post_message(QDF_MODULE_ID_WMA,
				       QDF_MODULE_ID_SME,
				       QDF_MODULE_ID_SME, &tsf_msg)) {

		WMA_LOGP("%s: Failed to post eWNI_SME_TSF_EVENT", __func__);
		qdf_mem_free(ptsf);
		return -EINVAL;
	}
	return 0;
}

#ifdef QCA_WIFI_3_0
#define TSF_FW_ACTION_CMD TSF_TSTAMP_QTIMER_CAPTURE_REQ
#else
#define TSF_FW_ACTION_CMD TSF_TSTAMP_CAPTURE_REQ
#endif
/**
 * wma_capture_tsf() - send wmi to fw to capture tsf
 * @wma_handle: wma handler
 * @vdev_id: vdev id
 *
 * Return: wmi send state
 */
QDF_STATUS wma_capture_tsf(tp_wma_handle wma_handle, uint32_t vdev_id)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	wmi_buf_t buf;
	wmi_vdev_tsf_tstamp_action_cmd_fixed_param *cmd;
	int ret;
	int len = sizeof(*cmd);

	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s: failed to allocate memory for cap tsf cmd",
			 __func__);
		return QDF_STATUS_E_NOMEM;
	}

	cmd = (wmi_vdev_tsf_tstamp_action_cmd_fixed_param *) wmi_buf_data(buf);
	cmd->vdev_id = vdev_id;
	cmd->tsf_action = TSF_FW_ACTION_CMD;
	WMA_LOGD("%s :vdev_id %u, tsf_cmd: %d", __func__, cmd->vdev_id,
						cmd->tsf_action);

	WMITLV_SET_HDR(&cmd->tlv_header,
	WMITLV_TAG_STRUC_wmi_vdev_tsf_tstamp_action_cmd_fixed_param,
	WMITLV_GET_STRUCT_TLVLEN(
	wmi_vdev_tsf_tstamp_action_cmd_fixed_param));

	ret = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
				   WMI_VDEV_TSF_TSTAMP_ACTION_CMDID);
	if (ret != EOK) {
		WMA_LOGE("wmi_unified_cmd_send returned Error %d", status);
		status = QDF_STATUS_E_FAILURE;
		goto error;
	}

	return QDF_STATUS_SUCCESS;

error:
	if (buf)
		wmi_buf_free(buf);
	return status;
}

/**
 * wma_reset_tsf_gpio() - send wmi to fw to reset GPIO
 * @wma_handle: wma handler
 * @vdev_id: vdev id
 *
 * Return: wmi send state
 */
QDF_STATUS wma_reset_tsf_gpio(tp_wma_handle wma_handle, uint32_t vdev_id)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	wmi_buf_t buf;
	wmi_vdev_tsf_tstamp_action_cmd_fixed_param *cmd;
	int ret;
	int len = sizeof(*cmd);
	uint8_t *buf_ptr;

	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s: failed to allocate memory for reset tsf gpio",
			 __func__);
		return QDF_STATUS_E_NOMEM;
	}

	buf_ptr = (uint8_t *) wmi_buf_data(buf);
	cmd = (wmi_vdev_tsf_tstamp_action_cmd_fixed_param *) buf_ptr;
	cmd->vdev_id = vdev_id;
	cmd->tsf_action = TSF_TSTAMP_CAPTURE_RESET;

	WMA_LOGD("%s :vdev_id %u, TSF_TSTAMP_CAPTURE_RESET", __func__,
		 cmd->vdev_id);

	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_vdev_tsf_tstamp_action_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
				wmi_vdev_tsf_tstamp_action_cmd_fixed_param));

	ret = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
				   WMI_VDEV_TSF_TSTAMP_ACTION_CMDID);

	if (ret != EOK) {
		WMA_LOGE("wmi_unified_cmd_send returned Error %d", status);
		status = QDF_STATUS_E_FAILURE;
		goto error;
	}
	return QDF_STATUS_SUCCESS;

error:
	if (buf)
		wmi_buf_free(buf);
	return status;
}

/**
 * wma_set_tsf_gpio_pin() - send wmi cmd to configure gpio pin
 * @handle: wma handler
 * @pin: GPIO pin id
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wma_set_tsf_gpio_pin(WMA_HANDLE handle, uint32_t pin)
{
	tp_wma_handle wma = (tp_wma_handle)handle;
	struct pdev_params pdev_param = {0};
	int32_t ret;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not set gpio", __func__);
		return QDF_STATUS_E_INVAL;
	}

	WMA_LOGD("%s: set tsf gpio pin: %d", __func__, pin);

	pdev_param.param_id = WMI_PDEV_PARAM_WNTS_CONFIG;
	pdev_param.param_value = pin;
	ret = wmi_unified_pdev_param_send(wma->wmi_handle,
					 &pdev_param,
					 WMA_WILDCARD_PDEV_ID);
	if (ret) {
		WMA_LOGE("%s: Failed to set tsf gpio pin (%d)", __func__, ret);
		return QDF_STATUS_E_FAILURE;
	}
	return QDF_STATUS_SUCCESS;
}
#endif

/**
 * wma_set_wisa_params(): Set WISA features related params in FW
 * @wma_handle: WMA handle
 * @wisa: Pointer to WISA param struct
 *
 * Return: CDF status
 */
QDF_STATUS wma_set_wisa_params(tp_wma_handle wma_handle,
				struct sir_wisa_params *wisa)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	wmi_buf_t buf;
	wmi_vdev_wisa_cmd_fixed_param *cmd;
	int ret, len = sizeof(*cmd);

	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s: failed to allocate memory for WISA params",
			 __func__);
		return QDF_STATUS_E_NOMEM;
	}

	cmd = (wmi_vdev_wisa_cmd_fixed_param *) wmi_buf_data(buf);
	cmd->wisa_mode = wisa->mode;
	cmd->vdev_id = wisa->vdev_id;

	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_vdev_wisa_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
				wmi_vdev_wisa_cmd_fixed_param));

	ret = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
				   WMI_VDEV_WISA_CMDID);
	if (ret != EOK) {
		WMA_LOGE("wmi_unified_cmd_send returned Error %d", status);
		status = QDF_STATUS_E_FAILURE;
		goto error;
	}
	return QDF_STATUS_SUCCESS;

error:
	wmi_buf_free(buf);
	return status;
}

/**
 * wma_process_dhcp_ind() - process dhcp indication from SME
 * @wma_handle: wma handle
 * @ta_dhcp_ind: DHCP indication
 *
 * Return: QDF Status
 */
QDF_STATUS wma_process_dhcp_ind(WMA_HANDLE handle,
				tAniDHCPInd *ta_dhcp_ind)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	uint8_t vdev_id;
	int status = 0;
	wmi_peer_set_param_cmd_fixed_param peer_set_param_fp = {0};

	if (!wma_handle) {
		WMA_LOGE("%s : wma_handle is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	if (!ta_dhcp_ind) {
		WMA_LOGE("%s : DHCP indication is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	if (!wma_find_vdev_by_addr(wma_handle,
				   ta_dhcp_ind->adapterMacAddr.bytes,
				   &vdev_id)) {
		WMA_LOGE("%s: Failed to find vdev id for DHCP indication",
			 __func__);
		return QDF_STATUS_E_FAILURE;
	}

	WMA_LOGD("%s: WMA --> WMI_PEER_SET_PARAM triggered by DHCP, msgType=%s, device_mode=%d, macAddr=" MAC_ADDRESS_STR,
		__func__, ta_dhcp_ind->msgType == WMA_DHCP_START_IND ?
		"WMA_DHCP_START_IND" : "WMA_DHCP_STOP_IND",
		ta_dhcp_ind->device_mode,
		MAC_ADDR_ARRAY(ta_dhcp_ind->peerMacAddr.bytes));

	/* fill in values */
	peer_set_param_fp.vdev_id = vdev_id;
	peer_set_param_fp.param_id = WMI_PEER_CRIT_PROTO_HINT_ENABLED;
	if (WMA_DHCP_START_IND == ta_dhcp_ind->msgType)
		peer_set_param_fp.param_value = 1;
	else
		peer_set_param_fp.param_value = 0;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(ta_dhcp_ind->peerMacAddr.bytes,
				   &peer_set_param_fp.peer_macaddr);

	status = wmi_unified_process_dhcp_ind(wma_handle->wmi_handle,
						&peer_set_param_fp);
	if (status != EOK)
		return QDF_STATUS_E_FAILURE;

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_chan_phy__mode() - get WLAN_PHY_MODE for channel
 * @chan: channel number
 * @chan_width: maximum channel width possible
 * @dot11_mode: maximum phy_mode possible
 *
 * Return: return WLAN_PHY_MODE
 */
WLAN_PHY_MODE wma_chan_phy_mode(u8 chan, enum phy_ch_width chan_width,
				u8 dot11_mode)
{
	WLAN_PHY_MODE phymode = MODE_UNKNOWN;
	uint16_t bw_val = wlan_reg_get_bw_value(chan_width);
	t_wma_handle *wma = cds_get_context(QDF_MODULE_ID_WMA);

	if (!wma) {
		WMA_LOGE("%s : wma_handle is NULL", __func__);
		return MODE_UNKNOWN;
	}

	if (chan_width >= CH_WIDTH_INVALID) {
		WMA_LOGE("%s : Invalid channel width", __func__);
		return MODE_UNKNOWN;
	}

	if (WLAN_REG_IS_24GHZ_CH(chan)) {
		if (((CH_WIDTH_5MHZ == chan_width) ||
		     (CH_WIDTH_10MHZ == chan_width)) &&
		    ((WNI_CFG_DOT11_MODE_11B == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11G == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11N == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_ALL == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11AC == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11AX == dot11_mode)))
			phymode = MODE_11G;
		else {
			switch (dot11_mode) {
			case WNI_CFG_DOT11_MODE_11B:
				if ((bw_val == 20) || (bw_val == 40))
					phymode = MODE_11B;
				break;
			case WNI_CFG_DOT11_MODE_11G:
				if ((bw_val == 20) || (bw_val == 40))
					phymode = MODE_11G;
				break;
			case WNI_CFG_DOT11_MODE_11G_ONLY:
				if ((bw_val == 20) || (bw_val == 40))
					phymode = MODE_11GONLY;
				break;
			case WNI_CFG_DOT11_MODE_11N:
			case WNI_CFG_DOT11_MODE_11N_ONLY:
				if (bw_val == 20)
					phymode = MODE_11NG_HT20;
				else if (bw_val == 40)
					phymode = MODE_11NG_HT40;
				break;
			case WNI_CFG_DOT11_MODE_ALL:
			case WNI_CFG_DOT11_MODE_11AC:
			case WNI_CFG_DOT11_MODE_11AC_ONLY:
				if (bw_val == 20)
					phymode = MODE_11AC_VHT20_2G;
				else if (bw_val == 40)
					phymode = MODE_11AC_VHT40_2G;
				break;
#if SUPPORT_11AX
			case WNI_CFG_DOT11_MODE_11AX:
			case WNI_CFG_DOT11_MODE_11AX_ONLY:
				if (20 == bw_val)
					phymode = MODE_11AX_HE20_2G;
				else if (40 == bw_val)
					phymode = MODE_11AX_HE40_2G;
				break;
#endif
			default:
				break;
			}
		}
	} else if (wlan_reg_is_dsrc_chan(wma->pdev, chan))
		phymode = MODE_11A;
	} else {
		if (((CH_WIDTH_5MHZ == chan_width) ||
		     (CH_WIDTH_10MHZ == chan_width)) &&
		    ((WNI_CFG_DOT11_MODE_11A == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11N == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_ALL == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11AC == dot11_mode) ||
		     (WNI_CFG_DOT11_MODE_11AX == dot11_mode)))
			phymode = MODE_11A;
		else {
			switch (dot11_mode) {
			case WNI_CFG_DOT11_MODE_11A:
				if (0 < bw_val)
					phymode = MODE_11A;
				break;
			case WNI_CFG_DOT11_MODE_11N:
			case WNI_CFG_DOT11_MODE_11N_ONLY:
				if (bw_val == 20)
					phymode = MODE_11NA_HT20;
				else if (40 <= bw_val)
					phymode = MODE_11NA_HT40;
				break;
			case WNI_CFG_DOT11_MODE_ALL:
			case WNI_CFG_DOT11_MODE_11AC:
			case WNI_CFG_DOT11_MODE_11AC_ONLY:
				if (bw_val == 20)
					phymode = MODE_11AC_VHT20;
				else if (bw_val == 40)
					phymode = MODE_11AC_VHT40;
				else if (bw_val == 80)
					phymode = MODE_11AC_VHT80;
				else if (chan_width == CH_WIDTH_160MHZ)
					phymode = MODE_11AC_VHT160;
				else if (chan_width == CH_WIDTH_80P80MHZ)
					phymode = MODE_11AC_VHT80_80;
				break;
#if SUPPORT_11AX
			case WNI_CFG_DOT11_MODE_11AX:
			case WNI_CFG_DOT11_MODE_11AX_ONLY:
				if (20 == bw_val)
					phymode = MODE_11AX_HE20;
				else if (40 == bw_val)
					phymode = MODE_11AX_HE40;
				else if (80 == bw_val)
					phymode = MODE_11AX_HE80;
				else if (CH_WIDTH_160MHZ == chan_width)
					phymode = MODE_11AX_HE160;
				else if (CH_WIDTH_80P80MHZ == chan_width)
					phymode = MODE_11AX_HE80_80;
				break;
#endif
			default:
				break;
			}
		}
	}

	WMA_LOGD("%s: phymode %d channel %d ch_width %d dot11_mode %d",
		 __func__, phymode, chan, chan_width, dot11_mode);

	QDF_ASSERT(MODE_UNKNOWN != phymode);
	return phymode;
}

/**
 * wma_get_link_speed() -send command to get linkspeed
 * @handle: wma handle
 * @pLinkSpeed: link speed info
 *
 * Return: QDF status
 */
QDF_STATUS wma_get_link_speed(WMA_HANDLE handle, tSirLinkSpeedInfo *pLinkSpeed)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	wmi_mac_addr peer_macaddr;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue get link speed cmd",
			 __func__);
		return QDF_STATUS_E_INVAL;
	}
	if (!wmi_service_enabled(wma_handle->wmi_handle,
				    wmi_service_estimate_linkspeed)) {
		WMA_LOGE("%s: Linkspeed feature bit not enabled Sending value 0 as link speed.",
			__func__);
		wma_send_link_speed(0);
		return QDF_STATUS_E_FAILURE;
	}
	/* Copy the peer macaddress to the wma buffer */
	WMI_CHAR_ARRAY_TO_MAC_ADDR(pLinkSpeed->peer_macaddr.bytes,
				   &peer_macaddr);
	WMA_LOGD("%s: pLinkSpeed->peerMacAddr: %pM, peer_macaddr.mac_addr31to0: 0x%x, peer_macaddr.mac_addr47to32: 0x%x",
		 __func__, pLinkSpeed->peer_macaddr.bytes,
		 peer_macaddr.mac_addr31to0,
		 peer_macaddr.mac_addr47to32);
	if (wmi_unified_get_link_speed_cmd(wma_handle->wmi_handle,
					peer_macaddr)) {
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_get_peer_info(WMA_HANDLE handle,
				struct sir_peer_info_req *peer_info_req)
{
	tp_wma_handle wma_handle = (tp_wma_handle)handle;
	wmi_request_stats_cmd_fixed_param *cmd;
	wmi_buf_t  wmi_buf;
	uint32_t  len;
	uint8_t *buf_ptr;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue get rssi",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	len  = sizeof(wmi_request_stats_cmd_fixed_param);
	wmi_buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}
	buf_ptr = (uint8_t *)wmi_buf_data(wmi_buf);

	cmd = (wmi_request_stats_cmd_fixed_param *)buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_request_stats_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(wmi_request_stats_cmd_fixed_param));

	cmd->stats_id = WMI_REQUEST_PEER_STAT;
	cmd->vdev_id = peer_info_req->sessionid;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_info_req->peer_macaddr.bytes,
				   &cmd->peer_macaddr);
	wma_handle->get_sta_peer_info = true;

	if (wmi_unified_cmd_send(wma_handle->wmi_handle, wmi_buf, len,
				WMI_REQUEST_STATS_CMDID)) {
		WMA_LOGE("Failed to send host stats request to fw");
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}

	qdf_mem_copy(&(wma_handle->peer_macaddr),
					&(peer_info_req->peer_macaddr),
					QDF_MAC_ADDR_SIZE);
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_get_peer_info_ext(WMA_HANDLE handle,
				struct sir_peer_info_ext_req *peer_info_req)
{
	tp_wma_handle wma_handle = (tp_wma_handle)handle;
	wmi_request_peer_stats_info_cmd_fixed_param *cmd;
	wmi_buf_t  wmi_buf;
	uint32_t  len;
	uint8_t *buf_ptr;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue get rssi",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	WMA_LOGI("%s send WMI_REQUEST_PEER_STATS_INFO_CMDID", __func__);

	len  = sizeof(wmi_request_peer_stats_info_cmd_fixed_param);
	wmi_buf = wmi_buf_alloc(wma_handle->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}
	buf_ptr = (uint8_t *)wmi_buf_data(wmi_buf);

	cmd = (wmi_request_peer_stats_info_cmd_fixed_param *)buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_request_peer_stats_info_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
			wmi_request_peer_stats_info_cmd_fixed_param));
	cmd->vdev_id = peer_info_req->sessionid;
	cmd->request_type = WMI_REQUEST_ONE_PEER_STATS_INFO;
	wma_handle->get_one_peer_info = true;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_info_req->peer_macaddr.bytes,
			&cmd->peer_macaddr);
	cmd->reset_after_request = peer_info_req->reset_after_request;

	if (wmi_unified_cmd_send(wma_handle->wmi_handle, wmi_buf, len,
				WMI_REQUEST_PEER_STATS_INFO_CMDID)) {
		WMA_LOGE("Failed to send peer stats request to fw");
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}

	WMA_LOGI("%s vdev_id %d, mac %pM, req_type %x, reset %x",
			__func__,
			cmd->vdev_id,
			peer_info_req->peer_macaddr.bytes,
			cmd->request_type,
			cmd->reset_after_request);

	qdf_mem_copy(&(wma_handle->peer_macaddr),
					&(peer_info_req->peer_macaddr),
					QDF_MAC_ADDR_SIZE);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_get_isolation(tp_wma_handle wma)
{
	wmi_coex_get_antenna_isolation_cmd_fixed_param *cmd;
	wmi_buf_t wmi_buf;
	uint32_t  len;
	uint8_t *buf_ptr;

	WMA_LOGD("%s: get isolation", __func__);

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue get isolation",
			 __func__);
		return QDF_STATUS_E_INVAL;
	}

	len  = sizeof(wmi_coex_get_antenna_isolation_cmd_fixed_param);
	wmi_buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}
	buf_ptr = (uint8_t *)wmi_buf_data(wmi_buf);

	cmd = (wmi_coex_get_antenna_isolation_cmd_fixed_param *)buf_ptr;
	WMITLV_SET_HDR(
	&cmd->tlv_header,
	WMITLV_TAG_STRUC_wmi_coex_get_antenna_isolation_cmd_fixed_param,
	WMITLV_GET_STRUCT_TLVLEN(
	wmi_coex_get_antenna_isolation_cmd_fixed_param));

	if (wmi_unified_cmd_send(wma->wmi_handle, wmi_buf, len,
				 WMI_COEX_GET_ANTENNA_ISOLATION_CMDID)) {
		WMA_LOGE("Failed to get isolation request from fw");
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_add_beacon_filter() - Issue WMI command to set beacon filter
 * @wma: wma handler
 * @filter_params: beacon_filter_param to set
 *
 * Return: Return QDF_STATUS
 */
QDF_STATUS wma_add_beacon_filter(WMA_HANDLE handle,
				struct beacon_filter_param *filter_params)
{
	int i;
	wmi_buf_t wmi_buf;
	u_int8_t *buf;
	A_UINT32 *ie_map;
	int ret;
	struct wma_txrx_node *iface;
	tp_wma_handle wma = (tp_wma_handle) handle;

	wmi_add_bcn_filter_cmd_fixed_param *cmd;
	int len = sizeof(wmi_add_bcn_filter_cmd_fixed_param);

	len += WMI_TLV_HDR_SIZE;
	len += BCN_FLT_MAX_ELEMS_IE_LIST*sizeof(A_UINT32);

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue set beacon filter",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	iface = &wma->interfaces[filter_params->vdev_id];
	qdf_mem_copy(&iface->beacon_filter, filter_params,
			sizeof(struct beacon_filter_param));
	iface->beacon_filter_enabled = true;

	wmi_buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}

	buf = (u_int8_t *) wmi_buf_data(wmi_buf);

	cmd = (wmi_add_bcn_filter_cmd_fixed_param *)wmi_buf_data(wmi_buf);
	cmd->vdev_id = filter_params->vdev_id;

	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_add_bcn_filter_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
				wmi_add_bcn_filter_cmd_fixed_param));

	buf += sizeof(wmi_add_bcn_filter_cmd_fixed_param);

	WMITLV_SET_HDR(buf, WMITLV_TAG_ARRAY_UINT32,
			(BCN_FLT_MAX_ELEMS_IE_LIST * sizeof(u_int32_t)));

	ie_map = (A_UINT32 *)(buf + WMI_TLV_HDR_SIZE);
	for (i = 0; i < BCN_FLT_MAX_ELEMS_IE_LIST; i++) {
		ie_map[i] = filter_params->ie_map[i];
		WMA_LOGD("beacon filter ie map = %u", ie_map[i]);
	}

	ret = wmi_unified_cmd_send(wma->wmi_handle, wmi_buf, len,
			WMI_ADD_BCN_FILTER_CMDID);
	if (ret) {
		WMA_LOGE("Failed to send wmi add beacon filter = %d",
				ret);
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
* wma_remove_beacon_filter() - Issue WMI command to remove beacon filter
* @wma: wma handler
* @filter_params: beacon_filter_params
*
* Return: Return QDF_STATUS
*/
QDF_STATUS wma_remove_beacon_filter(WMA_HANDLE handle,
				struct beacon_filter_param *filter_params)
{
	wmi_buf_t buf;
	tp_wma_handle wma = (tp_wma_handle) handle;
	wmi_rmv_bcn_filter_cmd_fixed_param *cmd;
	int len = sizeof(wmi_rmv_bcn_filter_cmd_fixed_param);
	int ret;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, cannot issue remove beacon filter",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}
	cmd = (wmi_rmv_bcn_filter_cmd_fixed_param *)wmi_buf_data(buf);
	cmd->vdev_id = filter_params->vdev_id;

	WMITLV_SET_HDR(&cmd->tlv_header,
			WMITLV_TAG_STRUC_wmi_rmv_bcn_filter_cmd_fixed_param,
			WMITLV_GET_STRUCT_TLVLEN(
				wmi_rmv_bcn_filter_cmd_fixed_param));

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
			WMI_RMV_BCN_FILTER_CMDID);
	if (ret) {
		WMA_LOGE("Failed to send wmi remove beacon filter = %d",
				ret);
		wmi_buf_free(buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_send_adapt_dwelltime_params() - send adaptive dwelltime configuration
 * params to firmware
 * @wma_handle:	 wma handler
 * @dwelltime_params: pointer to dwelltime_params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF failure reason code for failure
 */
QDF_STATUS wma_send_adapt_dwelltime_params(WMA_HANDLE handle,
			struct adaptive_dwelltime_params *dwelltime_params)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	struct wmi_adaptive_dwelltime_params wmi_param = {0};
	int32_t err;

	wmi_param.is_enabled = dwelltime_params->is_enabled;
	wmi_param.dwelltime_mode = dwelltime_params->dwelltime_mode;
	wmi_param.lpf_weight = dwelltime_params->lpf_weight;
	wmi_param.passive_mon_intval = dwelltime_params->passive_mon_intval;
	wmi_param.wifi_act_threshold = dwelltime_params->wifi_act_threshold;
	err = wmi_unified_send_adapt_dwelltime_params_cmd(wma_handle->
					wmi_handle, &wmi_param);
	if (err)
		return QDF_STATUS_E_FAILURE;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_send_dbs_scan_selection_params(WMA_HANDLE handle,
			struct wmi_dbs_scan_sel_params *dbs_scan_params)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	int32_t err;

	err = wmi_unified_send_dbs_scan_sel_params_cmd(wma_handle->
					wmi_handle, dbs_scan_params);
	if (err)
		return QDF_STATUS_E_FAILURE;

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_unified_fw_profiling_cmd() - send FW profiling cmd to WLAN FW
 * @wma: wma handle
 * @cmd: Profiling command index
 * @value1: parameter1 value
 * @value2: parameter2 value
 *
 * Return: 0 for success else error code
 */
QDF_STATUS wma_unified_fw_profiling_cmd(wmi_unified_t wmi_handle,
			uint32_t cmd, uint32_t value1, uint32_t value2)
{
	int ret;

	ret = wmi_unified_fw_profiling_data_cmd(wmi_handle, cmd,
			value1, value2);
	if (ret) {
		WMA_LOGE("enable cmd Failed for id %d value %d",
				value1, value2);
		return ret;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_wow_set_wake_time() - set timer pattern tlv, so that firmware will wake
 * up host after specified time is elapsed
 * @wma_handle: wma handle
 * @vdev_id: vdev id
 * @cookie: value to identify reason why host set up wake call.
 * @time: time in ms
 *
 * Return: QDF status
 */
static QDF_STATUS wma_wow_set_wake_time(WMA_HANDLE wma_handle, uint8_t vdev_id,
					uint32_t cookie, uint32_t time)
{
	int ret;
	tp_wma_handle wma = (tp_wma_handle)wma_handle;

	WMA_LOGD(FL("send timer patter with time: %d and vdev = %d to fw"),
		    time, vdev_id);
	ret = wmi_unified_wow_timer_pattern_cmd(wma->wmi_handle, vdev_id,
						cookie, time);
	if (ret) {
		WMA_LOGE(FL("Failed to send timer patter to fw"));
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_check_and_set_wake_timer(): checks all interfaces and if any interface
 * has install_key pending, sets timer pattern in fw to wake up host after
 * specified time has elapsed.
 * @wma: wma handle
 * @time: time after which host wants to be awaken.
 *
 * Return: None
 */
void wma_check_and_set_wake_timer(uint32_t time)
{
	int i;
	struct wma_txrx_node *iface;
	bool is_set_key_in_progress = false;
	t_wma_handle *wma = cds_get_context(QDF_MODULE_ID_WMA);

	if (!wma) {
		WMA_LOGE("%s: WMA is closed",
			__func__);
		return;
	}

	if (!wmi_service_enabled(wma->wmi_handle,
		wmi_service_wow_wakeup_by_timer_pattern)) {
		WMA_LOGD("TIME_PATTERN is not enabled");
		return;
	}

	for (i = 0; i < wma->max_bssid; i++) {
		iface = &wma->interfaces[i];
		if (iface->vdev_active && iface->is_waiting_for_key) {
			/*
			 * right now cookie is dont care, since FW disregards
			 * that.
			 */
			is_set_key_in_progress = true;
			wma_wow_set_wake_time((WMA_HANDLE)wma, i, 0, time);
			break;
		}
	}

	if (!is_set_key_in_progress)
		WMA_LOGD("set key not in progress for any vdev");
}

/**
 * wma_unified_csa_offload_enable() - sen CSA offload enable command
 * @wma: wma handle
 * @vdev_id: vdev id
 *
 * Return: 0 for success or error code
 */
int wma_unified_csa_offload_enable(tp_wma_handle wma, uint8_t vdev_id)
{
	if (wmi_unified_csa_offload_enable(wma->wmi_handle,
				 vdev_id)) {
		WMA_LOGP("%s: Failed to send CSA offload enable command",
			 __func__);
		return -EIO;
	}

	return 0;
}

#ifdef WLAN_FEATURE_NAN
/**
 * wma_nan_rsp_event_handler() - Function is used to handle nan response
 * @handle: wma handle
 * @event_buf: event buffer
 * @len: length of buffer
 *
 * Return: 0 for success or error code
 */
int wma_nan_rsp_event_handler(void *handle, uint8_t *event_buf,
			      uint32_t len)
{
	WMI_NAN_EVENTID_param_tlvs *param_buf;
	tSirNanEvent *nan_rsp_event;
	wmi_nan_event_hdr *nan_rsp_event_hdr;
	QDF_STATUS status;
	struct scheduler_msg message = {0};
	uint8_t *buf_ptr;
	uint32_t alloc_len;

	/*
	 * This is how received event_buf looks like
	 *
	 * <-------------------- event_buf ----------------------------------->
	 *
	 * <--wmi_nan_event_hdr--><---WMI_TLV_HDR_SIZE---><----- data -------->
	 *
	 * +-----------+---------+-----------------------+--------------------+
	 * | tlv_header| data_len| WMITLV_TAG_ARRAY_BYTE | nan_rsp_event_data |
	 * +-----------+---------+-----------------------+--------------------+
	 */

	WMA_LOGD("%s: Posting NaN response event to SME", __func__);
	param_buf = (WMI_NAN_EVENTID_param_tlvs *) event_buf;
	if (!param_buf) {
		WMA_LOGE("%s: Invalid nan response event buf", __func__);
		return -EINVAL;
	}
	nan_rsp_event_hdr = param_buf->fixed_param;
	buf_ptr = (uint8_t *) nan_rsp_event_hdr;
	alloc_len = sizeof(tSirNanEvent);
	alloc_len += nan_rsp_event_hdr->data_len;
	if (nan_rsp_event_hdr->data_len > ((WMI_SVC_MSG_MAX_SIZE -
	    WMI_TLV_HDR_SIZE - sizeof(*nan_rsp_event_hdr)) / sizeof(uint8_t)) ||
	    nan_rsp_event_hdr->data_len > param_buf->num_data) {
		WMA_LOGE("excess data length:%d, num_data:%d",
			nan_rsp_event_hdr->data_len, param_buf->num_data);
		return -EINVAL;
	}
	nan_rsp_event = (tSirNanEvent *) qdf_mem_malloc(alloc_len);
	if (NULL == nan_rsp_event) {
		WMA_LOGE("%s: Memory allocation failure", __func__);
		return -ENOMEM;
	}

	nan_rsp_event->event_data_len = nan_rsp_event_hdr->data_len;
	qdf_mem_copy(nan_rsp_event->event_data, buf_ptr +
		     sizeof(wmi_nan_event_hdr) + WMI_TLV_HDR_SIZE,
		     nan_rsp_event->event_data_len);
	message.type = eWNI_SME_NAN_EVENT;
	message.bodyptr = (void *)nan_rsp_event;
	message.bodyval = 0;

	status = scheduler_post_message(QDF_MODULE_ID_WMA,
					QDF_MODULE_ID_SME,
					QDF_MODULE_ID_SME, &message);
	if (status != QDF_STATUS_SUCCESS) {
		WMA_LOGE("%s: Failed to post NaN response event to SME",
			 __func__);
		qdf_mem_free(nan_rsp_event);
		return -EFAULT;
	}
	WMA_LOGD("%s: NaN response event Posted to SME", __func__);
	return 0;
}
#else
static int wma_nan_rsp_event_handler(void *handle, uint8_t *event_buf,
				     uint32_t len)
{
	return 0;
}
#endif /* WLAN_FEATURE_NAN */

/**
 * wma_csa_offload_handler() - CSA event handler
 * @handle: wma handle
 * @event: event buffer
 * @len: buffer length
 *
 * This event is sent by firmware when it receives CSA IE.
 *
 * Return: 0 for success or error code
 */
int wma_csa_offload_handler(void *handle, uint8_t *event, uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	WMI_CSA_HANDLING_EVENTID_param_tlvs *param_buf;
	wmi_csa_event_fixed_param *csa_event;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint8_t vdev_id = 0;
	uint8_t cur_chan = 0;
	struct ieee80211_channelswitch_ie *csa_ie;
	struct csa_offload_params *csa_offload_event;
	struct ieee80211_extendedchannelswitch_ie *xcsa_ie;
	struct ieee80211_ie_wide_bw_switch *wb_ie;
	struct wma_txrx_node *intr = wma->interfaces;

	param_buf = (WMI_CSA_HANDLING_EVENTID_param_tlvs *) event;

	WMA_LOGD("%s: Enter", __func__);
	if (!param_buf) {
		WMA_LOGE("Invalid csa event buffer");
		return -EINVAL;
	}
	csa_event = param_buf->fixed_param;
	WMI_MAC_ADDR_TO_CHAR_ARRAY(&csa_event->i_addr2, &bssid[0]);

	if (wma_find_vdev_by_bssid(wma, bssid, &vdev_id) == NULL) {
		WMA_LOGE("Invalid bssid received %s:%d", __func__, __LINE__);
		return -EINVAL;
	}

	csa_offload_event = qdf_mem_malloc(sizeof(*csa_offload_event));
	if (!csa_offload_event) {
		WMA_LOGE("QDF MEM Alloc Failed for csa_offload_event");
		return -EINVAL;
	}

	if (wma->interfaces[vdev_id].roaming_in_progress ||
		wma->interfaces[vdev_id].roam_synch_in_progress) {
		WMA_LOGE("Roaming in progress for vdev %d, ignore csa_offload_event",
				vdev_id);
		qdf_mem_free(csa_offload_event);
		return -EINVAL;
	}

	qdf_mem_zero(csa_offload_event, sizeof(*csa_offload_event));
	qdf_mem_copy(csa_offload_event->bssId, &bssid, IEEE80211_ADDR_LEN);

	if (csa_event->ies_present_flag & WMI_CSA_IE_PRESENT) {
		csa_ie = (struct ieee80211_channelswitch_ie *)
						(&csa_event->csa_ie[0]);
		csa_offload_event->channel = csa_ie->newchannel;
		csa_offload_event->switch_mode = csa_ie->switchmode;
	} else if (csa_event->ies_present_flag & WMI_XCSA_IE_PRESENT) {
		xcsa_ie = (struct ieee80211_extendedchannelswitch_ie *)
						(&csa_event->xcsa_ie[0]);
		csa_offload_event->channel = xcsa_ie->newchannel;
		csa_offload_event->switch_mode = xcsa_ie->switchmode;
		csa_offload_event->new_op_class = xcsa_ie->newClass;
	} else {
		WMA_LOGE("CSA Event error: No CSA IE present");
		qdf_mem_free(csa_offload_event);
		return -EINVAL;
	}

	if (csa_event->ies_present_flag & WMI_WBW_IE_PRESENT) {
		wb_ie = (struct ieee80211_ie_wide_bw_switch *)
						(&csa_event->wb_ie[0]);
		csa_offload_event->new_ch_width = wb_ie->new_ch_width;
		csa_offload_event->new_ch_freq_seg1 = wb_ie->new_ch_freq_seg1;
		csa_offload_event->new_ch_freq_seg2 = wb_ie->new_ch_freq_seg2;
	}

	csa_offload_event->ies_present_flag = csa_event->ies_present_flag;

	WMA_LOGD("CSA: New Channel = %d BSSID:%pM",
		 csa_offload_event->channel, csa_offload_event->bssId);

	cur_chan = cds_freq_to_chan(intr[vdev_id].mhz);
	/*
	 * basic sanity check: requested channel should not be 0
	 * and equal to home channel
	 */
	if (0 == csa_offload_event->channel) {
		WMA_LOGE("CSA Event with channel %d. Ignore !!",
			 csa_offload_event->channel);
		qdf_mem_free(csa_offload_event);
		return -EINVAL;
	}
	wma->interfaces[vdev_id].is_channel_switch = true;
	wma_send_msg(wma, WMA_CSA_OFFLOAD_EVENT, (void *)csa_offload_event, 0);
	return 0;
}

#ifdef FEATURE_OEM_DATA_SUPPORT
/**
 * wma_oem_data_response_handler() - OEM data response event handler
 * @handle: wma handle
 * @datap: data ptr
 * @len: data length
 *
 * Return: 0 for success or error code
 */
int wma_oem_data_response_handler(void *handle,
				  uint8_t *datap, uint32_t len)
{
	WMI_OEM_RESPONSE_EVENTID_param_tlvs *param_buf;
	uint8_t *data;
	uint32_t datalen;
	struct oem_data_rsp *oem_rsp;
	tpAniSirGlobal pmac = cds_get_context(QDF_MODULE_ID_PE);

	if (!pmac) {
		WMA_LOGE(FL("Invalid pmac"));
		return -EINVAL;
	}

	if (!pmac->sme.oem_data_rsp_callback) {
		WMA_LOGE(FL("Callback not registered"));
		return -EINVAL;
	}

	param_buf = (WMI_OEM_RESPONSE_EVENTID_param_tlvs *) datap;
	if (!param_buf) {
		WMA_LOGE(FL("Received NULL buf ptr from FW"));
		return -ENOMEM;
	}

	data = param_buf->data;
	datalen = param_buf->num_data;

	if (!data) {
		WMA_LOGE(FL("Received NULL data from FW"));
		return -EINVAL;
	}

	if (datalen > OEM_DATA_RSP_SIZE) {
		WMA_LOGE(FL("Received data len %d exceeds max value %d"),
			 datalen, OEM_DATA_RSP_SIZE);
		return -EINVAL;
	}

	oem_rsp = qdf_mem_malloc(sizeof(*oem_rsp));
	if (!oem_rsp) {
		WMA_LOGE(FL("Failed to alloc oem_data_rsp"));
		return -ENOMEM;
	}
	oem_rsp->rsp_len = datalen;
	if (oem_rsp->rsp_len) {
		oem_rsp->data = qdf_mem_malloc(oem_rsp->rsp_len);
		if (!oem_rsp->data) {
			WMA_LOGE(FL("malloc failed for data"));
			qdf_mem_free(oem_rsp);
			return -ENOMEM;
		}
	} else {
		WMA_LOGE(FL("Invalid rsp length: %d"),
			 oem_rsp->rsp_len);
		qdf_mem_free(oem_rsp);
		return -EINVAL;
	}

	qdf_mem_copy(oem_rsp->data, data, datalen);

	WMA_LOGD("Sending OEM_DATA_RSP(len: %d) to upper layer", datalen);

	pmac->sme.oem_data_rsp_callback(oem_rsp);

	if (oem_rsp->data)
		qdf_mem_free(oem_rsp->data);
	qdf_mem_free(oem_rsp);

	return 0;
}

/**
 * wma_start_oem_data_req() - start OEM data request to target
 * @wma_handle: wma handle
 * @oem_data_req: start request params
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wma_start_oem_data_req(tp_wma_handle wma_handle,
			    struct oem_data_req *oem_data_req)
{
	int ret = 0;

	WMA_LOGD(FL("Send OEM Data Request to target"));

	if (!oem_data_req || !oem_data_req->data) {
		WMA_LOGE(FL("oem_data_req is null"));
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE(FL("WMA - closed, can not send Oem data request cmd"));
		qdf_mem_free(oem_data_req->data);
		return QDF_STATUS_E_INVAL;
	}

	ret = wmi_unified_start_oem_data_cmd(wma_handle->wmi_handle,
				   oem_data_req->data_len,
				   oem_data_req->data);

	if (!QDF_IS_STATUS_SUCCESS(ret))
		WMA_LOGE(FL("wmi cmd send failed"));

	return ret;
}
#endif /* FEATURE_OEM_DATA_SUPPORT */

#if !defined(REMOVE_PKT_LOG)
/**
 * wma_pktlog_wmi_send_cmd() - send pktlog enable/disable command to target
 * @handle: wma handle
 * @params: pktlog params
 *
 * Return: QDF status
 */
QDF_STATUS wma_pktlog_wmi_send_cmd(WMA_HANDLE handle,
				   struct ath_pktlog_wmi_params *params)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	int ret;

	ret = wmi_unified_pktlog_wmi_send_cmd(wma_handle->wmi_handle,
			params->pktlog_event,
			params->cmd_id, params->user_triggered);
	if (ret)
		return QDF_STATUS_E_FAILURE;

	return QDF_STATUS_SUCCESS;
}
#endif /* REMOVE_PKT_LOG */

/**
 * process_search_fft_report() - Process Search FFT Report
 * @ptlv: pointer to Spectral Phyerr TLV
 * @tlvlen: Spectral Phyerr TLV length
 * @p_fft_info: pointer to search fft info
 *
 * Return: 0: success; non-zero:error
 */
#ifdef WLAN_DEBUG
static const u8 *wma_wow_wake_reason_str(A_INT32 wake_reason)
{
	switch (wake_reason) {
	case WOW_REASON_UNSPECIFIED:
		return "UNSPECIFIED";
	case WOW_REASON_NLOD:
		return "NLOD";
	case WOW_REASON_AP_ASSOC_LOST:
		return "AP_ASSOC_LOST";
	case WOW_REASON_LOW_RSSI:
		return "LOW_RSSI";
	case WOW_REASON_DEAUTH_RECVD:
		return "DEAUTH_RECVD";
	case WOW_REASON_DISASSOC_RECVD:
		return "DISASSOC_RECVD";
	case WOW_REASON_GTK_HS_ERR:
		return "GTK_HS_ERR";
	case WOW_REASON_EAP_REQ:
		return "EAP_REQ";
	case WOW_REASON_FOURWAY_HS_RECV:
		return "FOURWAY_HS_RECV";
	case WOW_REASON_TIMER_INTR_RECV:
		return "TIMER_INTR_RECV";
	case WOW_REASON_PATTERN_MATCH_FOUND:
		return "PATTERN_MATCH_FOUND";
	case WOW_REASON_RECV_MAGIC_PATTERN:
		return "RECV_MAGIC_PATTERN";
	case WOW_REASON_P2P_DISC:
		return "P2P_DISC";
	case WOW_REASON_WLAN_HB:
		return "WLAN_HB";
	case WOW_REASON_CSA_EVENT:
		return "CSA_EVENT";
	case WOW_REASON_PROBE_REQ_WPS_IE_RECV:
		return "PROBE_REQ_WPS_IE_RECV";
	case WOW_REASON_AUTH_REQ_RECV:
		return "AUTH_REQ_RECV";
	case WOW_REASON_ASSOC_REQ_RECV:
		return "ASSOC_REQ_RECV";
	case WOW_REASON_HTT_EVENT:
		return "HTT_EVENT";
	case WOW_REASON_RA_MATCH:
		return "RA_MATCH";
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		return "HOST_AUTO_SHUTDOWN";
	case WOW_REASON_IOAC_MAGIC_EVENT:
		return "IOAC_MAGIC_EVENT";
	case WOW_REASON_IOAC_SHORT_EVENT:
		return "IOAC_SHORT_EVENT";
	case WOW_REASON_IOAC_EXTEND_EVENT:
		return "IOAC_EXTEND_EVENT";
	case WOW_REASON_IOAC_TIMER_EVENT:
		return "IOAC_TIMER_EVENT";
	case WOW_REASON_ROAM_HO:
		return "ROAM_HO";
	case WOW_REASON_DFS_PHYERR_RADADR_EVENT:
		return "DFS_PHYERR_RADADR_EVENT";
	case WOW_REASON_BEACON_RECV:
		return "BEACON_RECV";
	case WOW_REASON_CLIENT_KICKOUT_EVENT:
		return "CLIENT_KICKOUT_EVENT";
	case WOW_REASON_NAN_EVENT:
		return "NAN_EVENT";
	case WOW_REASON_EXTSCAN:
		return "EXTSCAN";
	case WOW_REASON_RSSI_BREACH_EVENT:
		return "RSSI_BREACH_EVENT";
	case WOW_REASON_IOAC_REV_KA_FAIL_EVENT:
		return "IOAC_REV_KA_FAIL_EVENT";
	case WOW_REASON_IOAC_SOCK_EVENT:
		return "IOAC_SOCK_EVENT";
	case WOW_REASON_NLO_SCAN_COMPLETE:
		return "NLO_SCAN_COMPLETE";
	case WOW_REASON_PACKET_FILTER_MATCH:
		return "PACKET_FILTER_MATCH";
	case WOW_REASON_ASSOC_RES_RECV:
		return "ASSOC_RES_RECV";
	case WOW_REASON_REASSOC_REQ_RECV:
		return "REASSOC_REQ_RECV";
	case WOW_REASON_REASSOC_RES_RECV:
		return "REASSOC_RES_RECV";
	case WOW_REASON_ACTION_FRAME_RECV:
		return "ACTION_FRAME_RECV";
	case WOW_REASON_BPF_ALLOW:
		return "BPF_ALLOW";
	case WOW_REASON_NAN_DATA:
		return "NAN_DATA";
	case WOW_REASON_OEM_RESPONSE_EVENT:
		return "OEM_RESPONSE_EVENT";
	case WOW_REASON_TDLS_CONN_TRACKER_EVENT:
		return "TDLS_CONN_TRACKER_EVENT";
	case WOW_REASON_CRITICAL_LOG:
		return "CRITICAL_LOG";
	case WOW_REASON_P2P_LISTEN_OFFLOAD:
		return "P2P_LISTEN_OFFLOAD";
	case WOW_REASON_NAN_EVENT_WAKE_HOST:
		return "NAN_EVENT_WAKE_HOST";
	case WOW_REASON_DEBUG_TEST:
		return "DEBUG_TEST";
	case WOW_REASON_CHIP_POWER_FAILURE_DETECT:
		return "CHIP_POWER_FAILURE_DETECT";
	case WOW_REASON_11D_SCAN:
		return "11D_SCAN";
	case WOW_REASON_SAP_OBSS_DETECTION:
		return "SAP_OBSS_DETECTION";
	case WOW_REASON_BSS_COLOR_COLLISION_DETECT:
		return "BSS_COLOR_COLLISION_DETECT";
	default:
		return "unknown";
	}
}
#endif

#ifdef QCA_SUPPORT_CP_STATS
static bool wma_wow_reason_has_stats(enum wake_reason_e reason)
{
	switch (reason) {
	case WOW_REASON_ASSOC_REQ_RECV:
	case WOW_REASON_DISASSOC_RECVD:
	case WOW_REASON_ASSOC_RES_RECV:
	case WOW_REASON_REASSOC_REQ_RECV:
	case WOW_REASON_REASSOC_RES_RECV:
	case WOW_REASON_AUTH_REQ_RECV:
	case WOW_REASON_DEAUTH_RECVD:
	case WOW_REASON_ACTION_FRAME_RECV:
	case WOW_REASON_BPF_ALLOW:
	case WOW_REASON_PATTERN_MATCH_FOUND:
	case WOW_REASON_PACKET_FILTER_MATCH:
	case WOW_REASON_RA_MATCH:
	case WOW_REASON_NLOD:
	case WOW_REASON_NLO_SCAN_COMPLETE:
	case WOW_REASON_LOW_RSSI:
	case WOW_REASON_EXTSCAN:
	case WOW_REASON_RSSI_BREACH_EVENT:
	case WOW_REASON_OEM_RESPONSE_EVENT:
	case WOW_REASON_CHIP_POWER_FAILURE_DETECT:
	case WOW_REASON_11D_SCAN:
		return true;
	default:
		return false;
	}
}

static void wma_inc_wow_stats(t_wma_handle *wma,
			      WOW_EVENT_INFO_fixed_param *wake_info)
{
	ucfg_mc_cp_stats_inc_wake_lock_stats(wma->psoc,
					     wake_info->vdev_id,
					     wake_info->wake_reason);
}

static void wma_wow_stats_display(struct wake_lock_stats *stats)
{
	WMA_LOGA("WLAN wake reason counters:");
	WMA_LOGA("uc:%d bc:%d v4_mc:%d v6_mc:%d ra:%d ns:%d na:%d "
		 "icmp:%d icmpv6:%d",
		 stats->ucast_wake_up_count,
		 stats->bcast_wake_up_count,
		 stats->ipv4_mcast_wake_up_count,
		 stats->ipv6_mcast_wake_up_count,
		 stats->ipv6_mcast_ra_stats,
		 stats->ipv6_mcast_ns_stats,
		 stats->ipv6_mcast_na_stats,
		 stats->icmpv4_count,
		 stats->icmpv6_count);

	WMA_LOGA("assoc:%d disassoc:%d assoc_resp:%d reassoc:%d "
		 "reassoc_resp:%d auth:%d deauth:%d action:%d",
		 stats->mgmt_assoc,
		 stats->mgmt_disassoc,
		 stats->mgmt_assoc_resp,
		 stats->mgmt_reassoc,
		 stats->mgmt_reassoc_resp,
		 stats->mgmt_auth,
		 stats->mgmt_deauth,
		 stats->mgmt_action);

	WMA_LOGA("pno_match:%d pno_complete:%d gscan:%d "
		 "low_rssi:%d rssi_breach:%d oem:%d scan_11d:%d",
		 stats->pno_match_wake_up_count,
		 stats->pno_complete_wake_up_count,
		 stats->gscan_wake_up_count,
		 stats->low_rssi_wake_up_count,
		 stats->rssi_breach_wake_up_count,
		 stats->oem_response_wake_up_count,
		 stats->scan_11d);
}

static void wma_print_wow_stats(t_wma_handle *wma,
				WOW_EVENT_INFO_fixed_param *wake_info)
{
	struct wlan_objmgr_vdev *vdev;
	struct wake_lock_stats stats = {0};

	if (!wma_wow_reason_has_stats(wake_info->wake_reason))
		return;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(wma->psoc,
						    wake_info->vdev_id,
						    WLAN_LEGACY_WMA_ID);
	ucfg_mc_cp_stats_get_vdev_wake_lock_stats(vdev, &stats);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_WMA_ID);
	wma_wow_stats_display(&stats);
}
#else
/**
 * wma_wow_stats_display() - display wow wake up stats
 * @stats: per vdev stats counters
 *
 * Return: none
 */
static void wma_wow_stats_display(struct sir_vdev_wow_stats *stats)
{
	WMA_LOGA("uc %d bc %d v4_mc %d v6_mc %d ra %d ns %d na %d pno_match %d pno_complete %d gscan %d low_rssi %d rssi_breach %d icmp %d icmpv6 %d oem %d",
		stats->ucast,
		stats->bcast,
		stats->ipv4_mcast,
		stats->ipv6_mcast,
		stats->ipv6_mcast_ra,
		stats->ipv6_mcast_ns,
		stats->ipv6_mcast_na,
		stats->pno_match,
		stats->pno_complete,
		stats->gscan,
		stats->low_rssi,
		stats->rssi_breach,
		stats->icmpv4,
		stats->icmpv6,
		stats->oem_response);
}

static void wma_print_wow_stats(t_wma_handle *wma,
				WOW_EVENT_INFO_fixed_param *wake_info)
{
	struct sir_vdev_wow_stats *stats;

	switch (wake_info->wake_reason) {
	case WOW_REASON_BPF_ALLOW:
	case WOW_REASON_PATTERN_MATCH_FOUND:
	case WOW_REASON_PACKET_FILTER_MATCH:
	case WOW_REASON_RA_MATCH:
	case WOW_REASON_NLOD:
	case WOW_REASON_NLO_SCAN_COMPLETE:
	case WOW_REASON_LOW_RSSI:
	case WOW_REASON_EXTSCAN:
	case WOW_REASON_RSSI_BREACH_EVENT:
	case WOW_REASON_OEM_RESPONSE_EVENT:
	case WOW_REASON_CHIP_POWER_FAILURE_DETECT:
	case WOW_REASON_11D_SCAN:
		break;
	default:
		return;
	}

	stats = &wma->interfaces[wake_info->vdev_id].wow_stats;
	wma_wow_stats_display(stats);
}

/**
 * wma_inc_wow_stats() - maintain wow pattern match wake up stats
 * @wma: wma handle, containing the stats counters
 * @wake_info: the wake event information
 *
 * Return: none
 */
static void wma_inc_wow_stats(t_wma_handle *wma,
			      WOW_EVENT_INFO_fixed_param *wake_info)
{
	struct sir_vdev_wow_stats *stats;

	if (wake_info->wake_reason == WOW_REASON_UNSPECIFIED) {
		wma->wow_unspecified_wake_count++;
		return;
	}

	stats = &wma->interfaces[wake_info->vdev_id].wow_stats;
	switch (wake_info->wake_reason) {
	case WOW_REASON_RA_MATCH:
		stats->ipv6_mcast++;
		stats->ipv6_mcast_ra++;
		stats->icmpv6++;
		break;
	case WOW_REASON_NLOD:
		stats->pno_match++;
		break;
	case WOW_REASON_NLO_SCAN_COMPLETE:
		stats->pno_complete++;
		break;
	case WOW_REASON_LOW_RSSI:
		stats->low_rssi++;
		break;
	case WOW_REASON_EXTSCAN:
		stats->gscan++;
		break;
	case WOW_REASON_RSSI_BREACH_EVENT:
		stats->rssi_breach++;
		break;
	case WOW_REASON_OEM_RESPONSE_EVENT:
		stats->oem_response++;
		break;
	case WOW_REASON_11D_SCAN:
		stats->scan_11d++;
		break;
	case WOW_REASON_CHIP_POWER_FAILURE_DETECT:
		stats->pwr_save_fail_detected++;
		break;
	}
}
#endif

/**
 * wma_extract_single_phyerr_spectral() - extract single phy error from event
 * @handle: wma handle
 * @param evt_buf: pointer to event buffer
 * @param datalen: data length of event buffer
 * @param buf_offset: Pointer to hold value of current event buffer offset
 * post extraction
 * @param phyerr: Pointer to hold phyerr
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wma_extract_single_phyerr_spectral(void *handle,
		void *evt_buf,
		uint16_t datalen, uint16_t *buf_offset,
		wmi_host_phyerr_t *phyerr)
{
	wmi_single_phyerr_rx_event *ev;
	int n = *buf_offset;

	ev = (wmi_single_phyerr_rx_event *)((uint8_t *)evt_buf + n);

	if (n < datalen) {
		/* ensure there's at least space for the header */
		if ((datalen - n) < sizeof(ev->hdr)) {
			WMA_LOGE("%s: not enough space? (datalen=%d, n=%d, hdr=%zu bytes",
					__func__, datalen, n, sizeof(ev->hdr));
			return QDF_STATUS_E_FAILURE;
		}

		phyerr->bufp = ev->bufp;
		phyerr->buf_len = ev->hdr.buf_len;

		/*
		 * Sanity check the buffer length of the event against
		 * what we currently have.
		 *
		 * Since buf_len is 32 bits, we check if it overflows
		 * a large 32 bit value.  It's not 0x7fffffff because
		 * we increase n by (buf_len + sizeof(hdr)), which would
		 * in itself cause n to overflow.
		 *
		 * If "int" is 64 bits then this becomes a moot point.
		 */
		if (ev->hdr.buf_len > 0x7f000000) {
			WMA_LOGE("%s: buf_len is garbage? (0x%x)",
				__func__, ev->hdr.buf_len);
			return QDF_STATUS_E_FAILURE;
		}
		if (n + ev->hdr.buf_len > datalen) {
			WMA_LOGE("%s: buf_len exceeds available space n=%d, buf_len=%d, datalen=%d",
				__func__, n, ev->hdr.buf_len, datalen);
			return QDF_STATUS_E_FAILURE;
		}

		phyerr->phy_err_code = WMI_UNIFIED_PHYERRCODE_GET(&ev->hdr);
		phyerr->tsf_timestamp = ev->hdr.tsf_timestamp;

#ifdef DEBUG_SPECTRAL_SCAN
		WMA_LOGD("%s: len=%d, tsf=0x%08x, rssi = 0x%x/0x%x/0x%x/0x%x, comb rssi = 0x%x, phycode=%d",
				__func__,
				ev->hdr.buf_len,
				ev->hdr.tsf_timestamp,
				ev->hdr.rssi_chain0,
				ev->hdr.rssi_chain1,
				ev->hdr.rssi_chain2,
				ev->hdr.rssi_chain3,
				WMI_UNIFIED_RSSI_COMB_GET(&ev->hdr),
					  phyerr->phy_err_code);

		/*
		 * For now, unroll this loop - the chain 'value' field isn't
		 * a variable but glued together into a macro field definition.
		 * Grr. :-)
		 */
		WMA_LOGD("%s: chain 0: raw=0x%08x; pri20=%d sec20=%d sec40=%d sec80=%d",
				__func__,
				ev->hdr.rssi_chain0,
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, PRI20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC40),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC80));

		WMA_LOGD("%s: chain 1: raw=0x%08x: pri20=%d sec20=%d sec40=%d sec80=%d",
				__func__,
				ev->hdr.rssi_chain1,
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, PRI20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC40),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC80));

		WMA_LOGD("%s: chain 2: raw=0x%08x: pri20=%d sec20=%d sec40=%d sec80=%d",
				__func__,
				ev->hdr.rssi_chain2,
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, PRI20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC40),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC80));

		WMA_LOGD("%s: chain 3: raw=0x%08x: pri20=%d sec20=%d sec40=%d sec80=%d",
				__func__,
				ev->hdr.rssi_chain3,
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, PRI20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC20),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC40),
				WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC80));


		WMA_LOGD("%s: freq_info_1=0x%08x, freq_info_2=0x%08x",
			   __func__, ev->hdr.freq_info_1, ev->hdr.freq_info_2);

		/*
		 * The NF chain values are signed and are negative - hence
		 * the cast evilness.
		 */
		WMA_LOGD("%s: nfval[1]=0x%08x, nfval[2]=0x%08x, nf=%d/%d/%d/%d, freq1=%d, freq2=%d, cw=%d",
				__func__,
				ev->hdr.nf_list_1,
				ev->hdr.nf_list_2,
				(int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 0),
				(int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 1),
				(int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 2),
				(int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 3),
				WMI_UNIFIED_FREQ_INFO_GET(&ev->hdr, 1),
				WMI_UNIFIED_FREQ_INFO_GET(&ev->hdr, 2),
				WMI_UNIFIED_CHWIDTH_GET(&ev->hdr));
#endif

	default:
		event_id = 0;
		WMA_LOGE("%s: Unknown tag: %d", __func__, tag);
		break;
	}
	*buf_offset += n;

	return QDF_STATUS_SUCCESS;
}

/**
 * spectral_phyerr_event_handler() - spectral phyerr event handler
 * @handle: wma handle
 * @data: data buffer
 * @datalen: buffer length
 *
 * Return:  QDF_STATUS
 */
static QDF_STATUS spectral_phyerr_event_handler(void *handle,
					uint8_t *data, uint32_t datalen)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint16_t buf_offset, event_buf_len = 0;
	wmi_single_phyerr_rx_event *ev;
	wmi_host_phyerr_t phyerr;
	struct spectral_rfqual_info rfqual_info;
	struct spectral_chan_info   chan_info;

	if (NULL == wma) {
		WMA_LOGE("%s:wma handle is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	memset(&phyerr, 0, sizeof(wmi_host_phyerr_t));
	if (wma_extract_comb_phyerr_spectral(handle, data,
			datalen, &buf_offset, &phyerr)) {
		WMA_LOGE("%s: extract comb phyerr failed", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	ev = (wmi_single_phyerr_rx_event *)phyerr.bufp;
	event_buf_len = phyerr.buf_len;
	/* Loop over the bufp, extracting out phyerrors */
	buf_offset = 0;
	while (buf_offset < event_buf_len) {
		if (wma_extract_single_phyerr_spectral(handle, ev,
			event_buf_len, &buf_offset, &phyerr)) {
			WMA_LOGE("%s: extract single phy err failed", __func__);
			return QDF_STATUS_E_FAILURE;
		}

		if (phyerr.buf_len > 0) {
			if (sizeof(phyerr.rf_info) > sizeof(rfqual_info))
				qdf_mem_copy(&rfqual_info, &phyerr.rf_info,
						sizeof(rfqual_info));
			else
				qdf_mem_copy(&rfqual_info, &phyerr.rf_info,
						sizeof(phyerr.rf_info));

			if (sizeof(phyerr.chan_info) > sizeof(chan_info))
				qdf_mem_copy(&chan_info, &phyerr.chan_info,
						sizeof(chan_info));
			else
				qdf_mem_copy(&chan_info, &phyerr.chan_info,
						sizeof(phyerr.chan_info));

			status = spectral_process_phyerr(wma, phyerr.bufp,
							phyerr.buf_len,
							&rfqual_info,
							&chan_info,
							phyerr.tsf64);
		}
	}

	return status;
}
#else
static QDF_STATUS spectral_phyerr_event_handler(void *handle,
					uint8_t *data, uint32_t datalen)
{
	return QDF_STATUS_SUCCESS;
}
#endif

/**
 * dfs_phyerr_event_handler() - DFS phyerr event handler
 * @handle: wma handle
 * @data: data buffer
 * @datalen: buffer length
 *
 * WMI Handler for WMI_PHYERR_EVENTID event from firmware.
 * This handler is currently handling DFS phy error event
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS dfs_phyerr_event_handler(tp_wma_handle wma_handle,
					uint8_t *data, uint32_t datalen)
{
	int event_id;

	switch (reason) {
	case WOW_REASON_AP_ASSOC_LOST:
		event_id = WMI_ROAM_EVENTID;
		break;
	case WOW_REASON_NLO_SCAN_COMPLETE:
		event_id = WMI_NLO_SCAN_COMPLETE_EVENTID;
		break;
	case WOW_REASON_CSA_EVENT:
		event_id = WMI_CSA_HANDLING_EVENTID;
		break;
	case WOW_REASON_LOW_RSSI:
		event_id = WMI_ROAM_EVENTID;
		break;
	case WOW_REASON_CLIENT_KICKOUT_EVENT:
		event_id = WMI_PEER_STA_KICKOUT_EVENTID;
		break;
	case WOW_REASON_EXTSCAN:
		event_id = wma_extscan_get_eventid_from_tlvtag(tag);
		break;
	case WOW_REASON_RSSI_BREACH_EVENT:
		event_id = WMI_RSSI_BREACH_EVENTID;
		break;
	case WOW_REASON_NAN_EVENT:
		event_id = WMI_NAN_EVENTID;
		break;
	case WOW_REASON_NAN_DATA:
		event_id = wma_ndp_get_eventid_from_tlvtag(tag);
		break;
	case WOW_REASON_TDLS_CONN_TRACKER_EVENT:
		event_id = WOW_TDLS_CONN_TRACKER_EVENT;
		break;
	case WOW_REASON_ROAM_HO:
		event_id = WMI_ROAM_EVENTID;
		break;
	case WOW_REASON_11D_SCAN:
		event_id = WMI_11D_NEW_COUNTRY_EVENTID;
		break;
	default:
		WMA_LOGD(FL("No Event Id for WOW reason %s(%d)"),
			 wma_wow_wake_reason_str(reason), reason);
		event_id = 0;
		break;
	}
	wlan_roam_debug_log(WMA_INVALID_VDEV_ID, DEBUG_WOW_REASON,
			    DEBUG_INVALID_PEER_ID, NULL, NULL,
			    reason, event_id);

	if (false == wma_handle->dfs_phyerr_filter_offload) {
		/*
		 * Invoke the wma_unified_phyerr_rx_event_handler
		 * for filtering offload disabled case to handle
		 * the DFS phyerrors.
		 */
		WMA_LOGD("%s:Phyerror Filtering offload is Disabled in ini",
			 __func__);
		status = dfs_phyerr_no_offload_event_handler(wma_handle,
							data, datalen);
	} else {
		WMA_LOGD("%s:Phyerror Filtering offload is Enabled in ini",
			 __func__);
		status = dfs_phyerr_offload_event_handler(wma_handle,
							data, datalen);
	}

	return status;
}

/**
 * is_piggybacked_event() - Returns true if the given wake reason indicates
 *	there will be piggybacked TLV event data
 * @reason: WOW reason
 *
 * There are three types of WoW event payloads: none, piggybacked event, and
 * network packet. This function returns true for wake reasons that fall into
 * the piggybacked event case.
 *
 * Return: true for piggybacked event data
 */
static bool is_piggybacked_event(int32_t reason)
{
	switch (reason) {
	case WOW_REASON_AP_ASSOC_LOST:
	case WOW_REASON_NLO_SCAN_COMPLETE:
	case WOW_REASON_CSA_EVENT:
	case WOW_REASON_LOW_RSSI:
	case WOW_REASON_CLIENT_KICKOUT_EVENT:
	case WOW_REASON_EXTSCAN:
	case WOW_REASON_RSSI_BREACH_EVENT:
	case WOW_REASON_NAN_EVENT:
	case WOW_REASON_NAN_DATA:
	case WOW_REASON_TDLS_CONN_TRACKER_EVENT:
	case WOW_REASON_ROAM_HO:
		return true;
	default:
		return false;
	}

	/* handle different PHY Error conditions */
	if (((phyerr.phy_err_mask0 & (WMI_PHY_ERROR_MASK0_RADAR |
				WMI_PHY_ERROR_MASK0_FALSE_RADAR_EXT |
				WMI_PHY_ERROR_MASK0_SPECTRAL_SCAN)) == 0)) {
		WMA_LOGD("%s:Unknown phy error event", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	/* Handle Spectral or DFS PHY Error */
	if (phyerr.phy_err_mask0 & (WMI_PHY_ERROR_MASK0_RADAR |
				WMI_PHY_ERROR_MASK0_FALSE_RADAR_EXT))
		status = dfs_phyerr_event_handler(wma, data, datalen);
	else if (phyerr.phy_err_mask0 & (WMI_PHY_ERROR_MASK0_SPECTRAL_SCAN |
				WMI_PHY_ERROR_MASK0_FALSE_RADAR_EXT))
		status = spectral_phyerr_event_handler(wma, data, datalen);

	return status;
}

/**
 * wma_register_phy_err_event_handler() - register phy error event handler
 * @wma_handle: wma handle
 *
 * Register phyerror event handler for both DFS and spectral scan
 *
 * Return: none
 */
static const char *
wma_pkt_proto_subtype_to_string(enum qdf_proto_subtype proto_subtype)
{
	switch (proto_subtype) {
	case QDF_PROTO_EAPOL_M1:
		return "EAPOL M1";
	case QDF_PROTO_EAPOL_M2:
		return "EAPOL M2";
	case QDF_PROTO_EAPOL_M3:
		return "EAPOL M3";
	case QDF_PROTO_EAPOL_M4:
		return "EAPOL M4";
	case QDF_PROTO_DHCP_DISCOVER:
		return "DHCP DISCOVER";
	case QDF_PROTO_DHCP_REQUEST:
		return "DHCP REQUEST";
	case QDF_PROTO_DHCP_OFFER:
		return "DHCP OFFER";
	case QDF_PROTO_DHCP_ACK:
		return "DHCP ACK";
	case QDF_PROTO_DHCP_NACK:
		return "DHCP NACK";
	case QDF_PROTO_DHCP_RELEASE:
		return "DHCP RELEASE";
	case QDF_PROTO_DHCP_INFORM:
		return "DHCP INFORM";
	case QDF_PROTO_DHCP_DECLINE:
		return "DHCP DECLINE";
	case QDF_PROTO_ARP_REQ:
		return "ARP REQUEST";
	case QDF_PROTO_ARP_RES:
		return "ARP RESPONSE";
	case QDF_PROTO_ICMP_REQ:
		return "ICMP REQUEST";
	case QDF_PROTO_ICMP_RES:
		return "ICMP RESPONSE";
	case QDF_PROTO_ICMPV6_REQ:
		return "ICMPV6 REQUEST";
	case QDF_PROTO_ICMPV6_RES:
		return "ICMPV6 RESPONSE";
	case QDF_PROTO_ICMPV6_RS:
		return "ICMPV6 RS";
	case QDF_PROTO_ICMPV6_RA:
		return "ICMPV6 RA";
	case QDF_PROTO_ICMPV6_NS:
		return "ICMPV6 NS";
	case QDF_PROTO_ICMPV6_NA:
		return "ICMPV6 NA";
	case QDF_PROTO_IPV4_UDP:
		return "IPV4 UDP Packet";
	case QDF_PROTO_IPV4_TCP:
		return "IPV4 TCP Packet";
	case QDF_PROTO_IPV6_UDP:
		return "IPV6 UDP Packet";
	case QDF_PROTO_IPV6_TCP:
		return "IPV6 TCP Packet";
	default:
		return NULL;
	}

	wmi_unified_register_event_handler(wma_handle->wmi_handle,
					WMI_PHYERR_EVENTID,
					wma_unified_phyerr_rx_event_handler,
					WMA_RX_WORK_CTX);
	WMA_LOGD("%s: WMI_PHYERR_EVENTID event handler registered",
			 __func__);
}

#else
/**
 * wma_wow_get_pkt_proto_subtype() - get the proto subtype of the packet.
 * @data: Pointer to the packet data buffer
 * @len: length of the packet data buffer
 *
 * Return: 0 for success, other value for failure
 */
static enum qdf_proto_subtype
wma_wow_get_pkt_proto_subtype(uint8_t *data, uint32_t len)
{
	uint16_t eth_type;
	uint8_t proto_type;

	if (len < QDF_NBUF_TRAC_ETH_TYPE_OFFSET + 2) {
		WMA_LOGE("Malformed ethernet packet: length %u < %d",
			 len, QDF_NBUF_TRAC_ETH_TYPE_OFFSET + 2);
		return QDF_PROTO_INVALID;
	}

	eth_type = *(uint16_t *)(data + QDF_NBUF_TRAC_ETH_TYPE_OFFSET);
	eth_type = qdf_cpu_to_be16(eth_type);

	WMA_LOGD("Ether Type: 0x%04x", eth_type);
	switch (eth_type) {
	case QDF_NBUF_TRAC_EAPOL_ETH_TYPE:
		if (len < WMA_EAPOL_SUBTYPE_GET_MIN_LEN)
			return QDF_PROTO_INVALID;

		WMA_LOGD("EAPOL Packet");
		return qdf_nbuf_data_get_eapol_subtype(data);

	case QDF_NBUF_TRAC_ARP_ETH_TYPE:
		if (len < WMA_ARP_SUBTYPE_GET_MIN_LEN)
			return QDF_PROTO_INVALID;

		WMA_LOGD("ARP Packet");
		return qdf_nbuf_data_get_arp_subtype(data);

	case QDF_NBUF_TRAC_IPV4_ETH_TYPE:
		if (len < WMA_IPV4_PROTO_GET_MIN_LEN)
			return QDF_PROTO_INVALID;

		WMA_LOGD("IPV4 Packet");

		proto_type = qdf_nbuf_data_get_ipv4_proto(data);
		WMA_LOGD("IPV4_proto_type: %u", proto_type);

		switch (proto_type) {
		case QDF_NBUF_TRAC_ICMP_TYPE:
			if (len < WMA_ICMP_SUBTYPE_GET_MIN_LEN)
				return QDF_PROTO_INVALID;

			WMA_LOGD("ICMP Packet");
			return qdf_nbuf_data_get_icmp_subtype(data);

		case QDF_NBUF_TRAC_UDP_TYPE:
			if (len < WMA_IS_DHCP_GET_MIN_LEN)
				return QDF_PROTO_IPV4_UDP;

			if (!qdf_nbuf_data_is_ipv4_dhcp_pkt(data))
				return QDF_PROTO_INVALID;

			if (len < WMA_DHCP_SUBTYPE_GET_MIN_LEN)
				return QDF_PROTO_INVALID;

			WMA_LOGD("DHCP Packet");
			return qdf_nbuf_data_get_dhcp_subtype(data);

		case QDF_NBUF_TRAC_TCP_TYPE:
			return QDF_PROTO_IPV4_TCP;

		default:
			return QDF_PROTO_INVALID;
		}

	case QDF_NBUF_TRAC_IPV6_ETH_TYPE:
		if (len < WMA_IPV6_PROTO_GET_MIN_LEN)
			return QDF_PROTO_INVALID;

		WMA_LOGD("IPV6 Packet");

		proto_type = qdf_nbuf_data_get_ipv6_proto(data);
		WMA_LOGD("IPV6_proto_type: %u", proto_type);

		switch (proto_type) {
		case QDF_NBUF_TRAC_ICMPV6_TYPE:
			if (len < WMA_ICMPV6_SUBTYPE_GET_MIN_LEN)
				return QDF_PROTO_INVALID;

			WMA_LOGD("ICMPV6 Packet");
			return qdf_nbuf_data_get_icmpv6_subtype(data);

		case QDF_NBUF_TRAC_UDP_TYPE:
			return QDF_PROTO_IPV6_UDP;

		case QDF_NBUF_TRAC_TCP_TYPE:
			return QDF_PROTO_IPV6_TCP;

		default:
			return QDF_PROTO_INVALID;
		}

	default:
		return QDF_PROTO_INVALID;
	}
}

static void wma_log_pkt_eapol(uint8_t *data, uint32_t length)
{
	uint16_t pkt_len, key_len;

	if (length < WMA_EAPOL_INFO_GET_MIN_LEN)
		return;

	pkt_len = *(uint16_t *)(data + EAPOL_PKT_LEN_OFFSET);
	key_len = *(uint16_t *)(data + EAPOL_KEY_LEN_OFFSET);
	WMA_LOGD("Pkt_len: %u, Key_len: %u",
		 qdf_cpu_to_be16(pkt_len), qdf_cpu_to_be16(key_len));
}

static void wma_log_pkt_dhcp(uint8_t *data, uint32_t length)
{
	uint16_t pkt_len;
	uint32_t trans_id;

	if (length < WMA_DHCP_INFO_GET_MIN_LEN)
		return;

	pkt_len = *(uint16_t *)(data + DHCP_PKT_LEN_OFFSET);
	trans_id = *(uint32_t *)(data + DHCP_TRANSACTION_ID_OFFSET);
	WMA_LOGD("Pkt_len: %u, Transaction_id: %u",
		 qdf_cpu_to_be16(pkt_len), qdf_cpu_to_be16(trans_id));
}

static void wma_log_pkt_icmpv4(uint8_t *data, uint32_t length)
{
	uint16_t pkt_len, seq_num;

	if (length < WMA_IPV4_PKT_INFO_GET_MIN_LEN)
		return;

	pkt_len = *(uint16_t *)(data + IPV4_PKT_LEN_OFFSET);
	seq_num = *(uint16_t *)(data + ICMP_SEQ_NUM_OFFSET);
	WMA_LOGD("Pkt_len: %u, Seq_num: %u",
		 qdf_cpu_to_be16(pkt_len), qdf_cpu_to_be16(seq_num));
}

static void wma_log_pkt_icmpv6(uint8_t *data, uint32_t length)
{
	uint16_t pkt_len, seq_num;

	if (length < WMA_IPV6_PKT_INFO_GET_MIN_LEN)
		return;

	pkt_len = *(uint16_t *)(data + IPV6_PKT_LEN_OFFSET);
	seq_num = *(uint16_t *)(data + ICMPV6_SEQ_NUM_OFFSET);
	WMA_LOGD("Pkt_len: %u, Seq_num: %u",
		 qdf_cpu_to_be16(pkt_len), qdf_cpu_to_be16(seq_num));
}

static void wma_log_pkt_ipv4(uint8_t *data, uint32_t length)
{
	uint16_t pkt_len, src_port, dst_port;
	char *ip_addr;

	if (length < WMA_IPV4_PKT_INFO_GET_MIN_LEN)
		return;

	pkt_len = *(uint16_t *)(data + IPV4_PKT_LEN_OFFSET);
	ip_addr = (char *)(data + IPV4_SRC_ADDR_OFFSET);
	WMA_LOGD("src addr %d:%d:%d:%d", ip_addr[0], ip_addr[1],
		 ip_addr[2], ip_addr[3]);
	ip_addr = (char *)(data + IPV4_DST_ADDR_OFFSET);
	WMA_LOGD("dst addr %d:%d:%d:%d", ip_addr[0], ip_addr[1],
		 ip_addr[2], ip_addr[3]);
	src_port = *(uint16_t *)(data + IPV4_SRC_PORT_OFFSET);
	dst_port = *(uint16_t *)(data + IPV4_DST_PORT_OFFSET);
	WMA_LOGI("Pkt_len: %u, src_port: %u, dst_port: %u",
		 qdf_cpu_to_be16(pkt_len),
		 qdf_cpu_to_be16(src_port),
		 qdf_cpu_to_be16(dst_port));
}

static void wma_log_pkt_ipv6(uint8_t *data, uint32_t length)
{
	uint16_t pkt_len, src_port, dst_port;
	char *ip_addr;

	if (length < WMA_IPV6_PKT_INFO_GET_MIN_LEN)
		return;

	pkt_len = *(uint16_t *)(data + IPV6_PKT_LEN_OFFSET);
	ip_addr = (char *)(data + IPV6_SRC_ADDR_OFFSET);
	WMA_LOGD("src addr "IPV6_ADDR_STR, ip_addr[0],
		 ip_addr[1], ip_addr[2], ip_addr[3], ip_addr[4],
		 ip_addr[5], ip_addr[6], ip_addr[7], ip_addr[8],
		 ip_addr[9], ip_addr[10], ip_addr[11],
		 ip_addr[12], ip_addr[13], ip_addr[14],
		 ip_addr[15]);
	ip_addr = (char *)(data + IPV6_DST_ADDR_OFFSET);
	WMA_LOGD("dst addr "IPV6_ADDR_STR, ip_addr[0],
		 ip_addr[1], ip_addr[2], ip_addr[3], ip_addr[4],
		 ip_addr[5], ip_addr[6], ip_addr[7], ip_addr[8],
		 ip_addr[9], ip_addr[10], ip_addr[11],
		 ip_addr[12], ip_addr[13], ip_addr[14],
		 ip_addr[15]);
	src_port = *(uint16_t *)(data + IPV6_SRC_PORT_OFFSET);
	dst_port = *(uint16_t *)(data + IPV6_DST_PORT_OFFSET);
	WMA_LOGI("Pkt_len: %u, src_port: %u, dst_port: %u",
		 qdf_cpu_to_be16(pkt_len),
		 qdf_cpu_to_be16(src_port),
		 qdf_cpu_to_be16(dst_port));
}

static void wma_log_pkt_tcpv4(uint8_t *data, uint32_t length)
{
	uint32_t seq_num;

	if (length < WMA_IPV4_PKT_INFO_GET_MIN_LEN)
		return;

	seq_num = *(uint32_t *)(data + IPV4_TCP_SEQ_NUM_OFFSET);
	WMA_LOGD("TCP_seq_num: %u", qdf_cpu_to_be16(seq_num));
}

static void wma_log_pkt_tcpv6(uint8_t *data, uint32_t length)
{
	uint32_t seq_num;

	if (length < WMA_IPV6_PKT_INFO_GET_MIN_LEN)
		return;

	seq_num = *(uint32_t *)(data + IPV6_TCP_SEQ_NUM_OFFSET);
	WMA_LOGD("TCP_seq_num: %u", qdf_cpu_to_be16(seq_num));
}

#ifdef QCA_SUPPORT_CP_STATS
static void wma_wow_inc_wake_lock_stats_by_dst_addr(t_wma_handle *wma,
						    uint8_t vdev_id,
						    uint8_t *dest_mac)
{
	ucfg_mc_cp_stats_inc_wake_lock_stats_by_dst_addr(wma->psoc,
							 vdev_id,
							 dest_mac);
}

static void wma_wow_inc_wake_lock_stats_by_protocol(t_wma_handle *wma,
			uint8_t vdev_id, enum qdf_proto_subtype proto_subtype)
{
	ucfg_mc_cp_stats_inc_wake_lock_stats_by_protocol(wma->psoc,
							 vdev_id,
							 proto_subtype);
}
#else
static void wma_wow_inc_wake_lock_stats_by_dst_addr(t_wma_handle *wma,
						    uint8_t vdev_id,
						    uint8_t *dest_mac)
{
	struct wma_txrx_node *vdev;
	struct sir_vdev_wow_stats *stats;

	vdev = &wma->interfaces[vdev_id];
	stats = &vdev->wow_stats;

	switch (*dest_mac) {
	case WMA_BCAST_MAC_ADDR:
		stats->bcast++;
		break;
	case WMA_MCAST_IPV4_MAC_ADDR:
		stats->ipv4_mcast++;
		break;
	case WMA_MCAST_IPV6_MAC_ADDR:
		stats->ipv6_mcast++;
		break;
	default:
		stats->ucast++;
		break;
	}
}

static void wma_wow_inc_wake_lock_stats_by_protocol(t_wma_handle *wma,
			uint8_t vdev_id, enum qdf_proto_subtype proto_subtype)
{
	struct wma_txrx_node *vdev;
	struct sir_vdev_wow_stats *stats;

	vdev = &wma->interfaces[vdev_id];
	stats = &vdev->wow_stats;

	switch (proto_subtype) {
	case QDF_PROTO_ICMP_RES:
		stats->icmpv4++;
		break;
	case QDF_PROTO_ICMPV6_REQ:
	case QDF_PROTO_ICMPV6_RES:
	case QDF_PROTO_ICMPV6_RS:
		stats->icmpv6++;
		break;
	case QDF_PROTO_ICMPV6_RA:
		stats->icmpv6++;
		stats->ipv6_mcast_ra++;
		break;
	case QDF_PROTO_ICMPV6_NS:
		stats->icmpv6++;
		stats->ipv6_mcast_ns++;
		break;
	case QDF_PROTO_ICMPV6_NA:
		stats->icmpv6++;
		stats->ipv6_mcast_na++;
		break;
	default:
		break;
	}
}
#endif

/**
 * wma_wow_parse_data_pkt() - API to parse data buffer for data
 *    packet that resulted in WOW wakeup.
 * @stats: per-vdev stats for tracking packet types
 * @data: Pointer to data buffer
 * @length: data buffer length
 *
 * This function parses the data buffer received (first few bytes of
 * skb->data) to get information like src mac addr, dst mac addr, packet
 * len, seq_num, etc. It also increments stats for different packet types.
 *
 * Return: 0 for success, other value for failure
 */
static void wma_wow_parse_data_pkt(t_wma_handle *wma,
				   uint8_t vdev_id, uint8_t *data,
				   uint32_t length)
{
	uint8_t *src_mac;
	uint8_t *dest_mac;
	const char *proto_subtype_name;
	enum qdf_proto_subtype proto_subtype;

	WMA_LOGD("packet length: %u", length);
	if (length < QDF_NBUF_TRAC_IPV4_OFFSET)
		return;

	src_mac = data + QDF_NBUF_SRC_MAC_OFFSET;
	dest_mac = data + QDF_NBUF_DEST_MAC_OFFSET;
	WMA_LOGI("Src_mac: " MAC_ADDRESS_STR ", Dst_mac: " MAC_ADDRESS_STR,
		 MAC_ADDR_ARRAY(src_mac), MAC_ADDR_ARRAY(dest_mac));

	wma_wow_inc_wake_lock_stats_by_dst_addr(wma, vdev_id, dest_mac);

	proto_subtype = wma_wow_get_pkt_proto_subtype(data, length);
	proto_subtype_name = wma_pkt_proto_subtype_to_string(proto_subtype);
	if (proto_subtype_name)
		WMA_LOGI("WOW Wakeup: %s rcvd", proto_subtype_name);

	switch (proto_subtype) {
	case QDF_PROTO_EAPOL_M1:
	case QDF_PROTO_EAPOL_M2:
	case QDF_PROTO_EAPOL_M3:
	case QDF_PROTO_EAPOL_M4:
		wma_log_pkt_eapol(data, length);
		break;

	case QDF_PROTO_DHCP_DISCOVER:
	case QDF_PROTO_DHCP_REQUEST:
	case QDF_PROTO_DHCP_OFFER:
	case QDF_PROTO_DHCP_ACK:
	case QDF_PROTO_DHCP_NACK:
	case QDF_PROTO_DHCP_RELEASE:
	case QDF_PROTO_DHCP_INFORM:
	case QDF_PROTO_DHCP_DECLINE:
		wma_log_pkt_dhcp(data, length);
		break;

	case QDF_PROTO_ICMP_REQ:
	case QDF_PROTO_ICMP_RES:
		wma_wow_inc_wake_lock_stats_by_protocol(wma, vdev_id,
							proto_subtype);
		wma_log_pkt_icmpv4(data, length);
		break;

	case QDF_PROTO_ICMPV6_REQ:
	case QDF_PROTO_ICMPV6_RES:
	case QDF_PROTO_ICMPV6_RS:
	case QDF_PROTO_ICMPV6_RA:
	case QDF_PROTO_ICMPV6_NS:
	case QDF_PROTO_ICMPV6_NA:
		wma_wow_inc_wake_lock_stats_by_protocol(wma, vdev_id,
							proto_subtype);
		wma_log_pkt_icmpv6(data, length);
		break;

	case QDF_PROTO_IPV4_UDP:
		wma_log_pkt_ipv4(data, length);
		break;
	case QDF_PROTO_IPV4_TCP:
		wma_log_pkt_ipv4(data, length);
		wma_log_pkt_tcpv4(data, length);
		break;

	case QDF_PROTO_IPV6_UDP:
		wma_log_pkt_ipv6(data, length);
		break;
	case QDF_PROTO_IPV6_TCP:
		wma_log_pkt_ipv6(data, length);
		wma_log_pkt_tcpv6(data, length);
		break;
	default:
		break;
	}
}

/**
 * wma_register_phy_err_event_handler() - register appropriate phy error event
 *     handler
 * @wma_handle: wma handle
 *
 * This function parses the data buffer received (802.11 header)
 * to get information like src mac addr, dst mac addr, seq_num,
 * frag_num, etc.
 *
 * Return: none
 */
static void wma_wow_dump_mgmt_buffer(uint8_t *wow_packet_buffer,
				     uint32_t buf_len)
{
	struct ieee80211_frame_addr4 *wh;

	WMA_LOGD("wow_buf_pkt_len: %u", buf_len);
	wh = (struct ieee80211_frame_addr4 *)
		(wow_packet_buffer);
	if (buf_len >= sizeof(struct ieee80211_frame)) {
		uint8_t to_from_ds, frag_num;
		uint32_t seq_num;

		WMA_LOGE("RA: " MAC_ADDRESS_STR " TA: " MAC_ADDRESS_STR,
			MAC_ADDR_ARRAY(wh->i_addr1),
			MAC_ADDR_ARRAY(wh->i_addr2));

		WMA_LOGE("TO_DS: %u, FROM_DS: %u",
			wh->i_fc[1] & IEEE80211_FC1_DIR_TODS,
			wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS);

		to_from_ds = wh->i_fc[1] & IEEE80211_FC1_DIR_DSTODS;

		switch (to_from_ds) {
		case IEEE80211_NO_DS:
			WMA_LOGE("BSSID: " MAC_ADDRESS_STR,
				MAC_ADDR_ARRAY(wh->i_addr3));
			break;
		case IEEE80211_TO_DS:
			WMA_LOGE("DA: " MAC_ADDRESS_STR,
				MAC_ADDR_ARRAY(wh->i_addr3));
			break;
		case IEEE80211_FROM_DS:
			WMA_LOGE("SA: " MAC_ADDRESS_STR,
				MAC_ADDR_ARRAY(wh->i_addr3));
			break;
		case IEEE80211_DS_TO_DS:
			if (buf_len >= sizeof(struct ieee80211_frame_addr4))
				WMA_LOGE("DA: " MAC_ADDRESS_STR " SA: "
					MAC_ADDRESS_STR,
					MAC_ADDR_ARRAY(wh->i_addr3),
					MAC_ADDR_ARRAY(wh->i_addr4));
			break;
		}

		seq_num = (((*(uint16_t *)wh->i_seq) &
				IEEE80211_SEQ_SEQ_MASK) >>
				IEEE80211_SEQ_SEQ_SHIFT);
		frag_num = (((*(uint16_t *)wh->i_seq) &
				IEEE80211_SEQ_FRAG_MASK) >>
				IEEE80211_SEQ_FRAG_SHIFT);

	if (false == wma_handle->dfs_phyerr_filter_offload) {
		wmi_unified_register_event_handler(wma_handle->wmi_handle,
					WMI_PHYERR_EVENTID,
					wma_unified_phyerr_rx_event_handler,
					WMA_RX_WORK_CTX);
		WMA_LOGD("%s: WMI_PHYERR_EVENTID event handler registered",
			__func__);
	} else {
		wmi_unified_register_event_handler(wma_handle->wmi_handle,
					WMI_DFS_RADAR_EVENTID,
					wma_unified_dfs_radar_rx_event_handler,
					WMA_RX_WORK_CTX);
		WMA_LOGD("%s: WMI_DFS_RADAR_EVENTID event handler registered",
		__func__);
	}
}
#endif

/**
 * wma_acquire_wakelock() - conditionally aquires a wakelock base on wake reason
 * @wma: the wma handle with the wakelocks to aquire
 * @wake_reason: wow wakeup reason
 *
 * Return: None
 */
static void wma_acquire_wow_wakelock(t_wma_handle *wma, int wake_reason)
{
	qdf_wake_lock_t *wl;
	uint32_t ms;

	switch (wake_reason) {
	case WOW_REASON_AUTH_REQ_RECV:
		wl = &wma->wow_auth_req_wl;
		ms = WMA_AUTH_REQ_RECV_WAKE_LOCK_TIMEOUT;
		break;
	case WOW_REASON_ASSOC_REQ_RECV:
		wl = &wma->wow_assoc_req_wl;
		ms = WMA_ASSOC_REQ_RECV_WAKE_LOCK_DURATION;
		break;
	case WOW_REASON_DEAUTH_RECVD:
		wl = &wma->wow_deauth_rec_wl;
		ms = WMA_DEAUTH_RECV_WAKE_LOCK_DURATION;
		break;
	case WOW_REASON_DISASSOC_RECVD:
		wl = &wma->wow_disassoc_rec_wl;
		ms = WMA_DISASSOC_RECV_WAKE_LOCK_DURATION;
		break;
	case WOW_REASON_AP_ASSOC_LOST:
		wl = &wma->wow_ap_assoc_lost_wl;
		ms = WMA_BMISS_EVENT_WAKE_LOCK_DURATION;
		break;
#ifdef FEATURE_WLAN_AUTO_SHUTDOWN
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		wl = &wma->wow_auto_shutdown_wl;
		ms = WMA_AUTO_SHUTDOWN_WAKE_LOCK_DURATION;
		break;
#endif
	case WOW_REASON_ROAM_HO:
		wl = &wma->roam_ho_wl;
		ms = WMA_ROAM_HO_WAKE_LOCK_DURATION;
		break;
	default:
		return;
	}

	WMA_LOGA("Holding %d msec wake_lock", ms);
	cds_host_diag_log_work(wl, ms, WIFI_POWER_EVENT_WAKELOCK_WOW);
	qdf_wake_lock_timeout_acquire(wl, ms);
}

#if !defined(REMOVE_PKT_LOG)
/**
 * wma_wake_reason_ap_assoc_lost() - WOW_REASON_AP_ASSOC_LOST handler
 * @wma: Pointer to wma handle
 * @event: pointer to piggybacked WMI_ROAM_EVENTID_param_tlvs buffer
 * @len: length of the event buffer
 *
 * Return: Errno
 */
static int
wma_wake_reason_ap_assoc_lost(t_wma_handle *wma, void *event, uint32_t len)
{
	WMI_ROAM_EVENTID_param_tlvs *event_param;
	wmi_roam_event_fixed_param *roam_event;

	event_param = event;
	if (!event_param) {
		WMA_LOGE("AP Assoc Lost event data is null");
		return -EINVAL;
	}

	roam_event = event_param->fixed_param;
	WMA_LOGA(FL("Beacon miss indication on vdev %d"), roam_event->vdev_id);

	wma_beacon_miss_handler(wma, roam_event->vdev_id, roam_event->rssi);

	return 0;
}

#ifdef WLAN_DEBUG
static const char *wma_vdev_type_str(uint32_t vdev_type)
{
	switch (vdev_type) {
	case WMI_VDEV_TYPE_AP:
		return "AP";
	case WMI_VDEV_TYPE_STA:
		return "STA";
	case WMI_VDEV_TYPE_IBSS:
		return "IBSS";
	case WMI_VDEV_TYPE_MONITOR:
		return "MONITOR";
	case WMI_VDEV_TYPE_NAN:
		return "NAN";
	case WMI_VDEV_TYPE_OCB:
		return "OCB";
	case WMI_VDEV_TYPE_NDI:
		return "NDI";
	default:
		return "unknown";
	}
}
#endif

static int wma_wake_event_packet(
	t_wma_handle *wma,
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *event_param,
	uint32_t length)
{
	WOW_EVENT_INFO_fixed_param *wake_info;
	struct wma_txrx_node *vdev;
	uint8_t *packet;
	uint32_t packet_len;

	if (event_param->num_wow_packet_buffer <= 4) {
		WMA_LOGE("Invalid wow packet buffer from firmware %u",
			 event_param->num_wow_packet_buffer);
		return -EINVAL;
	}
	/* first 4 bytes are the length, followed by the buffer */
	packet_len = *(uint32_t *)event_param->wow_packet_buffer;
	packet = event_param->wow_packet_buffer + 4;

	if (!packet_len) {
		WMA_LOGE("Wake event packet is empty");
		return 0;
	}

	if (packet_len > (event_param->num_wow_packet_buffer - 4)) {
		WMA_LOGE("Invalid packet_len from firmware, packet_len: %u, num_wow_packet_buffer: %u",
			 packet_len,
			 event_param->num_wow_packet_buffer);
		return -EINVAL;
	}
}

	wake_info = event_param->fixed_param;

	switch (wake_info->wake_reason) {
	case WOW_REASON_AUTH_REQ_RECV:
	case WOW_REASON_ASSOC_REQ_RECV:
	case WOW_REASON_DEAUTH_RECVD:
		return "DEAUTH_RECVD";
	case WOW_REASON_DISASSOC_RECVD:
		return "DISASSOC_RECVD";
	case WOW_REASON_GTK_HS_ERR:
		return "GTK_HS_ERR";
	case WOW_REASON_EAP_REQ:
		return "EAP_REQ";
	case WOW_REASON_FOURWAY_HS_RECV:
		return "FOURWAY_HS_RECV";
	case WOW_REASON_TIMER_INTR_RECV:
		return "TIMER_INTR_RECV";
	case WOW_REASON_PATTERN_MATCH_FOUND:
		return "PATTERN_MATCH_FOUND";
	case WOW_REASON_RECV_MAGIC_PATTERN:
		return "RECV_MAGIC_PATTERN";
	case WOW_REASON_P2P_DISC:
		return "P2P_DISC";
	case WOW_REASON_WLAN_HB:
		return "WLAN_HB";
	case WOW_REASON_CSA_EVENT:
		return "CSA_EVENT";
	case WOW_REASON_PROBE_REQ_WPS_IE_RECV:
		return "PROBE_REQ_WPS_IE_RECV";
	case WOW_REASON_AUTH_REQ_RECV:
		return "AUTH_REQ_RECV";
	case WOW_REASON_ASSOC_REQ_RECV:
		return "ASSOC_REQ_RECV";
	case WOW_REASON_HTT_EVENT:
		return "HTT_EVENT";
	case WOW_REASON_RA_MATCH:
		return "RA_MATCH";
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		return "HOST_AUTO_SHUTDOWN";
	case WOW_REASON_IOAC_MAGIC_EVENT:
		return "IOAC_MAGIC_EVENT";
	case WOW_REASON_IOAC_SHORT_EVENT:
		return "IOAC_SHORT_EVENT";
	case WOW_REASON_IOAC_EXTEND_EVENT:
		return "IOAC_EXTEND_EVENT";
	case WOW_REASON_IOAC_TIMER_EVENT:
		return "IOAC_TIMER_EVENT";
	case WOW_REASON_ROAM_HO:
		return "ROAM_HO";
	case WOW_REASON_DFS_PHYERR_RADADR_EVENT:
		return "DFS_PHYERR_RADADR_EVENT";
	case WOW_REASON_BEACON_RECV:
		return "BEACON_RECV";
	case WOW_REASON_CLIENT_KICKOUT_EVENT:
		return "CLIENT_KICKOUT_EVENT";
	case WOW_REASON_NAN_EVENT:
		return "NAN_EVENT";
	case WOW_REASON_EXTSCAN:
		return "EXTSCAN";
	case WOW_REASON_RSSI_BREACH_EVENT:
		return "RSSI_BREACH_EVENT";
	case WOW_REASON_IOAC_REV_KA_FAIL_EVENT:
		return "IOAC_REV_KA_FAIL_EVENT";
	case WOW_REASON_IOAC_SOCK_EVENT:
		return "IOAC_SOCK_EVENT";
	case WOW_REASON_NLO_SCAN_COMPLETE:
		return "NLO_SCAN_COMPLETE";
	case WOW_REASON_PACKET_FILTER_MATCH:
		return "PACKET_FILTER_MATCH";
	case WOW_REASON_ASSOC_RES_RECV:
		return "ASSOC_RES_RECV";
	case WOW_REASON_REASSOC_REQ_RECV:
		return "REASSOC_REQ_RECV";
	case WOW_REASON_REASSOC_RES_RECV:
		return "REASSOC_RES_RECV";
	case WOW_REASON_ACTION_FRAME_RECV:
		/* management frame case */
		wma_wow_dump_mgmt_buffer(packet, packet_len);
		break;

	case WOW_REASON_BPF_ALLOW:
	case WOW_REASON_PATTERN_MATCH_FOUND:
	case WOW_REASON_RA_MATCH:
	case WOW_REASON_RECV_MAGIC_PATTERN:
	case WOW_REASON_PACKET_FILTER_MATCH:
		WMA_LOGD("Wake event packet:");
		qdf_trace_hex_dump(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_DEBUG,
				   packet, packet_len);

		vdev = &wma->interfaces[wake_info->vdev_id];
		wma_wow_parse_data_pkt(wma, wake_info->vdev_id,
				       packet, packet_len);
		break;

	default:
		WMA_LOGE("Wake reason %s(%u) is not a packet event",
			 wma_wow_wake_reason_str(wake_info->wake_reason),
			 wake_info->wake_reason);
		return -EINVAL;
	}

	return 0;
}

static int wma_wake_event_no_payload(
	t_wma_handle *wma,
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *event_param,
	uint32_t length)
{
	WOW_EVENT_INFO_fixed_param *wake_info = event_param->fixed_param;

	switch (wake_info->wake_reason) {
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		return wma_wake_reason_auto_shutdown();

	case WOW_REASON_NLOD:
		return wma_wake_reason_nlod(wma, wake_info->vdev_id);

	default:
		return 0;
	}
}

static int wma_wake_event_piggybacked(
	t_wma_handle *wma,
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *event_param,
	uint32_t length)
{
	int errno = 0;
	void *pb_event;
	uint32_t pb_event_len;
	uint32_t wake_reason;
	uint32_t event_id;
	uint8_t *bssid;
	uint8_t peer_id;
	void *peer, *pdev;
	tpDeleteStaContext del_sta_ctx;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);

	/*
	 * There are "normal" cases where a wake reason that usually contains a
	 * piggybacked event is empty. In these cases we just want to wake up,
	 * and no action is needed. Bail out now if that is the case.
	 */
	if (!event_param->wow_packet_buffer ||
	    event_param->num_wow_packet_buffer <= 4) {
		WMA_LOGE("Invalid wow packet buffer from firmware %u",
			 event_param->num_wow_packet_buffer);
		return 0;
	}

	pdev = cds_get_context(QDF_MODULE_ID_TXRX);
	bssid = wma->interfaces[event_param->fixed_param->vdev_id].bssid;
	peer = cdp_peer_find_by_addr(soc, pdev, bssid, &peer_id);
	wake_reason = event_param->fixed_param->wake_reason;

	/* parse piggybacked event from param buffer */
	{
		int ret_code;
		uint8_t *pb_event_buf;
		uint32_t tag;

		/* first 4 bytes are the length, followed by the buffer */
		pb_event_len = *(uint32_t *)event_param->wow_packet_buffer;
		if (pb_event_len > (event_param->num_wow_packet_buffer - 4)) {
			WMA_LOGE("Invalid pb_event_len from firmware, pb_event_len: %u, num_wow_packet_buffer: %u",
				 pb_event_len,
				 event_param->num_wow_packet_buffer);
			return -EINVAL;
		}
		pb_event_buf = event_param->wow_packet_buffer + 4;

		WMA_LOGD("piggybacked event buffer:");
		qdf_trace_hex_dump(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_DEBUG,
				   pb_event_buf, pb_event_len);

		tag = WMITLV_GET_TLVTAG(WMITLV_GET_HDR(pb_event_buf));
		event_id = wow_get_wmi_eventid(wake_reason, tag);
		if (!event_id) {
			WMA_LOGE(FL("Unable to find Event Id"));
			return -EINVAL;
		}

		ret_code = wmitlv_check_and_pad_event_tlvs(wma, pb_event_buf,
							   pb_event_len,
							   event_id, &pb_event);
		if (ret_code) {
			WMA_LOGE(FL("Bad TLVs; len:%d, event_id:%d, status:%d"),
				 pb_event_len, event_id, ret_code);
			return -EINVAL;
		}
	}

	switch (wake_reason) {
	case WOW_REASON_AP_ASSOC_LOST:
		errno = wma_wake_reason_ap_assoc_lost(wma, pb_event,
						      pb_event_len);
		break;

#ifdef FEATURE_WLAN_SCAN_PNO
	case WOW_REASON_NLO_SCAN_COMPLETE:
		errno = target_if_nlo_complete_handler(wma, pb_event,
						       pb_event_len);
		break;
#endif /* FEATURE_WLAN_SCAN_PNO */

	case WOW_REASON_CSA_EVENT:
		errno = wma_csa_offload_handler(wma, pb_event, pb_event_len);
		break;

	/*
	 * WOW_REASON_LOW_RSSI is used for following roaming events -
	 * WMI_ROAM_REASON_BETTER_AP, WMI_ROAM_REASON_BMISS,
	 * WMI_ROAM_REASON_SUITABLE_AP will be handled by
	 * wma_roam_event_callback().
	 * WOW_REASON_ROAM_HO is associated with
	 * WMI_ROAM_REASON_HO_FAILED event and it will be handled by
	 * wma_roam_event_callback().
	 */
	case WOW_REASON_LOW_RSSI:
	case WOW_REASON_ROAM_HO:
		wlan_roam_debug_log(event_param->fixed_param->vdev_id,
				    DEBUG_WOW_ROAM_EVENT,
				    DEBUG_INVALID_PEER_ID,
				    NULL, NULL, wake_reason,
				    pb_event_len);
		if (pb_event_len > 0) {
			errno = wma_roam_event_callback(wma, pb_event,
							pb_event_len);
		} else {
			stats->ucast++;
			if (len >= WMA_IPV4_PROTO_GET_MIN_LEN &&
			    qdf_nbuf_data_is_icmp_pkt(data))
				stats->icmpv4++;
			else if (len > WMA_ICMP_V6_TYPE_OFFSET &&
			    qdf_nbuf_data_is_icmpv6_pkt(data))
				stats->icmpv6++;
		}
		break;

	case WOW_REASON_CLIENT_KICKOUT_EVENT:
		errno = wma_peer_sta_kickout_event_handler(wma, pb_event,
							   pb_event_len);
		break;

#ifdef FEATURE_WLAN_EXTSCAN
	case WOW_REASON_EXTSCAN:
		errno = wma_extscan_wow_event_callback(wma, pb_event,
						       pb_event_len);
		break;

	case WOW_REASON_CHIP_POWER_FAILURE_DETECT:
		stats->pwr_save_fail_detected++;
		break;

	default:
		WMA_LOGD("Stats for WoW reason %s are not tracked",
			 wma_wow_wake_reason_str(reason));

		/* don't bother displaying stats that haven't changed */
		return;
	}

	wma_wow_stats_display(stats);
}

#ifdef FEATURE_WLAN_EXTSCAN
/**
 * wma_extscan_get_eventid_from_tlvtag() - map tlv tag to corresponding event id
 * @tag: WMI TLV tag
 *
 * Return:
 *	0 if TLV tag is invalid
 *	else return corresponding WMI event id
 */
static int wma_extscan_get_eventid_from_tlvtag(uint32_t tag)
{
	uint32_t event_id;

	switch (tag) {
	case WMITLV_TAG_STRUC_wmi_extscan_start_stop_event_fixed_param:
		event_id = WMI_EXTSCAN_START_STOP_EVENTID;
		break;

	case WMITLV_TAG_STRUC_wmi_extscan_operation_event_fixed_param:
		event_id = WMI_EXTSCAN_OPERATION_EVENTID;
		break;

	case WMITLV_TAG_STRUC_wmi_extscan_table_usage_event_fixed_param:
		event_id = WMI_EXTSCAN_TABLE_USAGE_EVENTID;
		break;

	case WMITLV_TAG_STRUC_wmi_extscan_cached_results_event_fixed_param:
		event_id = WMI_EXTSCAN_CACHED_RESULTS_EVENTID;
		break;

	case WMITLV_TAG_STRUC_wmi_extscan_wlan_change_results_event_fixed_param:
		event_id = WMI_EXTSCAN_WLAN_CHANGE_RESULTS_EVENTID;
		break;

	case WMITLV_TAG_STRUC_wmi_extscan_hotlist_match_event_fixed_param:
		event_id = WMI_EXTSCAN_HOTLIST_MATCH_EVENTID;
		break;

	case WMITLV_TAG_STRUC_wmi_extscan_capabilities_event_fixed_param:
		event_id = WMI_EXTSCAN_CAPABILITIES_EVENTID;
		break;

	default:
		event_id = 0;
		WMA_LOGE("%s: Unknown tag: %d", __func__, tag);
		break;
	}

	WMA_LOGD("%s: For tag %d WMI event 0x%x", __func__, tag, event_id);
	return event_id;
}
#else
static int wma_extscan_get_eventid_from_tlvtag(uint32_t tag)
{
	return 0;
}
#endif

	case WOW_REASON_RSSI_BREACH_EVENT:
		errno = wma_rssi_breached_event_handler(wma, pb_event,
							pb_event_len);
		break;

	case WOW_REASON_NAN_EVENT:
		errno = wma_nan_rsp_event_handler(wma, pb_event, pb_event_len);
		break;

	case WOW_REASON_NAN_DATA:
		errno = wma_ndp_wow_event_callback(wma, pb_event, pb_event_len,
						   event_id);
		break;

#ifdef FEATURE_WLAN_TDLS
	case WOW_REASON_TDLS_CONN_TRACKER_EVENT:
		errno = wma_tdls_event_handler(wma, pb_event, pb_event_len);
		break;
#endif

	case WOW_REASON_TIMER_INTR_RECV:
		/*
		 * Right now firmware is not returning any cookie host has
		 * programmed. So do not check for cookie.
		 */
		WMA_LOGE("WOW_REASON_TIMER_INTR_RECV received, indicating key exchange did not finish. Initiate disconnect");
		del_sta_ctx = (tpDeleteStaContext) qdf_mem_malloc(
							sizeof(*del_sta_ctx));
		if (!del_sta_ctx) {
			WMA_LOGE("%s: mem alloc failed ", __func__);
			break;
		}
		del_sta_ctx->is_tdls = false;
		del_sta_ctx->vdev_id = event_param->fixed_param->vdev_id;
		del_sta_ctx->staId = peer_id;
		qdf_mem_copy(del_sta_ctx->addr2, bssid, IEEE80211_ADDR_LEN);
		qdf_mem_copy(del_sta_ctx->bssId, bssid, IEEE80211_ADDR_LEN);
		del_sta_ctx->reasonCode = HAL_DEL_STA_REASON_CODE_KEEP_ALIVE;
		wma_send_msg(wma, SIR_LIM_DELETE_STA_CONTEXT_IND, del_sta_ctx,
			     0);
		break;

	default:
		WMA_LOGE("Wake reason %s(%u) is not a piggybacked event",
			 wma_wow_wake_reason_str(wake_reason), wake_reason);
		errno = -EINVAL;
		break;
	}
	wma_peer_debug_log(WMA_INVALID_VDEV_ID, DEBUG_WOW_REASON,
			   DEBUG_INVALID_PEER_ID, NULL, NULL,
			   reason, event_id);

	return event_id;
}

/**
 * tlv_check_required() - tells whether to check the wow packet buffer
 *                        for proper TLV structure.
 * @reason: WOW reason
 *
 * In most cases, wow wake up event carries the actual event buffer in
 * wow_packet_buffer with some exceptions. This function is used to
 * determine when to check for the TLVs in wow_packet_buffer.
 *
 * Return: true if check is required and false otherwise.
 */
static bool tlv_check_required(int32_t reason)
{
	switch (reason) {
	case WOW_REASON_NLO_SCAN_COMPLETE:
	case WOW_REASON_CSA_EVENT:
	case WOW_REASON_LOW_RSSI:
	case WOW_REASON_CLIENT_KICKOUT_EVENT:
	case WOW_REASON_EXTSCAN:
	case WOW_REASON_RSSI_BREACH_EVENT:
	case WOW_REASON_NAN_EVENT:
	case WOW_REASON_NAN_DATA:
	case WOW_REASON_ROAM_HO:
		return true;
	default:
		return false;
	}
}

/**
 * wma_pkt_proto_subtype_to_string() - to convert proto subtype
 *         of data packet to string.
 * @proto_subtype: proto subtype for data packet
 *
 * This function returns the string for the proto subtype of
 * data packet.
 *
 * Return: string for proto subtype for data packet
 */
static const char *
wma_pkt_proto_subtype_to_string(enum qdf_proto_subtype proto_subtype)
{
	switch (proto_subtype) {
	case QDF_PROTO_EAPOL_M1:
		return "EAPOL M1";
	case QDF_PROTO_EAPOL_M2:
		return "EAPOL M2";
	case QDF_PROTO_EAPOL_M3:
		return "EAPOL M3";
	case QDF_PROTO_EAPOL_M4:
		return "EAPOL M4";
	case QDF_PROTO_DHCP_DISCOVER:
		return "DHCP DISCOVER";
	case QDF_PROTO_DHCP_REQUEST:
		return "DHCP REQUEST";
	case QDF_PROTO_DHCP_OFFER:
		return "DHCP OFFER";
	case QDF_PROTO_DHCP_ACK:
		return "DHCP ACK";
	case QDF_PROTO_DHCP_NACK:
		return "DHCP NACK";
	case QDF_PROTO_DHCP_RELEASE:
		return "DHCP RELEASE";
	case QDF_PROTO_DHCP_INFORM:
		return "DHCP INFORM";
	case QDF_PROTO_DHCP_DECLINE:
		return "DHCP DECLINE";
	case QDF_PROTO_ARP_REQ:
		return "ARP REQUEST";
	case QDF_PROTO_ARP_RES:
		return "ARP RESPONSE";
	case QDF_PROTO_ICMP_REQ:
		return "ICMP REQUEST";
	case QDF_PROTO_ICMP_RES:
		return "ICMP RESPONSE";
	case QDF_PROTO_ICMPV6_REQ:
		return "ICMPV6 REQUEST";
	case QDF_PROTO_ICMPV6_RES:
		return "ICMPV6 RESPONSE";
	case QDF_PROTO_ICMPV6_RS:
		return "ICMPV6 RS";
	case QDF_PROTO_ICMPV6_RA:
		return "ICMPV6 RA";
	case QDF_PROTO_ICMPV6_NS:
		return "ICMPV6 NS";
	case QDF_PROTO_ICMPV6_NA:
		return "ICMPV6 NA";
	case QDF_PROTO_IPV4_UDP:
		return "IPV4 UDP Packet";
	case QDF_PROTO_IPV4_TCP:
		return "IPV4 TCP Packet";
	case QDF_PROTO_IPV6_UDP:
		return "IPV6 UDP Packet";
	case QDF_PROTO_IPV6_TCP:
		return "IPV6 TCP Packet";
	default:
		return "Invalid Packet";
	}
}

/**
 * wma_wow_get_pkt_proto_subtype() - get the proto subtype
 *            of the packet.
 * @data: Pointer to data buffer
 * @len: length of the data buffer
 *
 * This function gives the proto subtype of the packet.
 *
 * Return: proto subtype of the packet.
 */
static enum qdf_proto_subtype
wma_wow_get_pkt_proto_subtype(uint8_t *data,
			uint32_t len)
{
	uint16_t ether_type = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_TRAC_ETH_TYPE_OFFSET));

	WMA_LOGD("Ether Type: 0x%04x",
		ani_cpu_to_be16(ether_type));

	if (QDF_NBUF_TRAC_EAPOL_ETH_TYPE ==
		   ani_cpu_to_be16(ether_type)) {
		if (len >= WMA_EAPOL_SUBTYPE_GET_MIN_LEN)
			return qdf_nbuf_data_get_eapol_subtype(data);
		WMA_LOGD("EAPOL Packet");
		return QDF_PROTO_INVALID;
	} else if (QDF_NBUF_TRAC_ARP_ETH_TYPE ==
		   ani_cpu_to_be16(ether_type)) {
		if (len >= WMA_ARP_SUBTYPE_GET_MIN_LEN)
			return qdf_nbuf_data_get_arp_subtype(data);
		WMA_LOGD("ARP Packet");
		return QDF_PROTO_INVALID;
	} else if (QDF_NBUF_TRAC_IPV4_ETH_TYPE ==
		   ani_cpu_to_be16(ether_type)) {
		uint8_t proto_type;

		if (len < WMA_IPV4_PROTO_GET_MIN_LEN)
			return QDF_PROTO_INVALID;
		proto_type = qdf_nbuf_data_get_ipv4_proto(data);
		WMA_LOGD("IPV4_proto_type: %u", proto_type);
		if (proto_type == QDF_NBUF_TRAC_ICMP_TYPE) {
			if (len >= WMA_ICMP_SUBTYPE_GET_MIN_LEN)
				return qdf_nbuf_data_get_icmp_subtype(
						data);
			WMA_LOGD("ICMP Packet");
			return QDF_PROTO_INVALID;
		} else if (proto_type == QDF_NBUF_TRAC_UDP_TYPE) {
			if (len >= WMA_IS_DHCP_GET_MIN_LEN &&
				qdf_nbuf_data_is_ipv4_dhcp_pkt(data)) {
				if (len >= WMA_DHCP_SUBTYPE_GET_MIN_LEN)
					return qdf_nbuf_data_get_dhcp_subtype(
									data);
				WMA_LOGD("DHCP Packet");
				return QDF_PROTO_INVALID;
			}
			return QDF_PROTO_IPV4_UDP;
		} else if (proto_type == QDF_NBUF_TRAC_TCP_TYPE) {
			return QDF_PROTO_IPV4_TCP;
		}
		WMA_LOGD("IPV4 Packet");
		return QDF_PROTO_INVALID;
	} else if (QDF_NBUF_TRAC_IPV6_ETH_TYPE ==
		   ani_cpu_to_be16(ether_type)) {
		if (len >= WMA_IPV6_PROTO_GET_MIN_LEN) {
			uint8_t proto_type;

			proto_type = qdf_nbuf_data_get_ipv6_proto(data);
			WMA_LOGD("IPV6_proto_type: %u", proto_type);
			if (proto_type == QDF_NBUF_TRAC_ICMPV6_TYPE) {
				if (len >= WMA_ICMPV6_SUBTYPE_GET_MIN_LEN)
					return qdf_nbuf_data_get_icmpv6_subtype(
							data);
				WMA_LOGD("ICMPV6 Packet");
				return QDF_PROTO_INVALID;
			} else if (proto_type == QDF_NBUF_TRAC_UDP_TYPE) {
				return QDF_PROTO_IPV6_UDP;
			} else if (proto_type == QDF_NBUF_TRAC_TCP_TYPE) {
				return QDF_PROTO_IPV6_TCP;
			}
		}
		WMA_LOGD("IPV6 Packet");
		return QDF_PROTO_INVALID;
	}

	return QDF_PROTO_INVALID;
}

/**
 * wma_wow_parse_data_pkt_buffer() - API to parse data buffer for data
 *    packet that resulted in WOW wakeup.
 * @data: Pointer to data buffer
 * @buf_len: data buffer length
 *
 * This function parses the data buffer received (first few bytes of
 * skb->data) to get informaton like src mac addr, dst mac addr, packet
 * len, seq_num, etc.
 *
 * Return: void
 */
static void wma_wow_parse_data_pkt_buffer(uint8_t *data,
			uint32_t buf_len)
{
	enum qdf_proto_subtype proto_subtype;
	uint16_t pkt_len, key_len, seq_num;
	uint16_t src_port, dst_port;
	uint32_t transaction_id, tcp_seq_num;
	char *ip_addr;

	WMA_LOGD("wow_buf_pkt_len: %u", buf_len);
	if (buf_len >= QDF_NBUF_TRAC_IPV4_OFFSET)
		WMA_LOGI("Src_mac: "MAC_ADDRESS_STR" Dst_mac: "MAC_ADDRESS_STR,
			MAC_ADDR_ARRAY(data + QDF_NBUF_SRC_MAC_OFFSET),
			MAC_ADDR_ARRAY(data + QDF_NBUF_DEST_MAC_OFFSET));
	else
		goto end;

	proto_subtype = wma_wow_get_pkt_proto_subtype(data, buf_len);
	switch (proto_subtype) {
	case QDF_PROTO_EAPOL_M1:
	case QDF_PROTO_EAPOL_M2:
	case QDF_PROTO_EAPOL_M3:
	case QDF_PROTO_EAPOL_M4:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		if (buf_len >= WMA_EAPOL_INFO_GET_MIN_LEN) {
			pkt_len = (uint16_t)(*(uint16_t *)(data +
				EAPOL_PKT_LEN_OFFSET));
			key_len = (uint16_t)(*(uint16_t *)(data +
				EAPOL_KEY_LEN_OFFSET));
			WMA_LOGD("Pkt_len: %u, Key_len: %u",
				ani_cpu_to_be16(pkt_len),
				ani_cpu_to_be16(key_len));
		}
		break;

	case QDF_PROTO_DHCP_DISCOVER:
	case QDF_PROTO_DHCP_REQUEST:
	case QDF_PROTO_DHCP_OFFER:
	case QDF_PROTO_DHCP_ACK:
	case QDF_PROTO_DHCP_NACK:
	case QDF_PROTO_DHCP_RELEASE:
	case QDF_PROTO_DHCP_INFORM:
	case QDF_PROTO_DHCP_DECLINE:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		if (buf_len >= WMA_DHCP_INFO_GET_MIN_LEN) {
			pkt_len = (uint16_t)(*(uint16_t *)(data +
				DHCP_PKT_LEN_OFFSET));
			transaction_id = (uint32_t)(*(uint32_t *)(data +
				DHCP_TRANSACTION_ID_OFFSET));
			WMA_LOGD("Pkt_len: %u, Transaction_id: %u",
				ani_cpu_to_be16(pkt_len),
				ani_cpu_to_be16(transaction_id));
		}
		break;

	case QDF_PROTO_ARP_REQ:
	case QDF_PROTO_ARP_RES:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		break;

	case QDF_PROTO_ICMP_REQ:
	case QDF_PROTO_ICMP_RES:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		if (buf_len >= WMA_IPV4_PKT_INFO_GET_MIN_LEN) {
			pkt_len = (uint16_t)(*(uint16_t *)(data +
				IPV4_PKT_LEN_OFFSET));
			seq_num = (uint16_t)(*(uint16_t *)(data +
				ICMP_SEQ_NUM_OFFSET));
			WMA_LOGD("Pkt_len: %u, Seq_num: %u",
				ani_cpu_to_be16(pkt_len),
				ani_cpu_to_be16(seq_num));
		}
		break;

	case QDF_PROTO_ICMPV6_REQ:
	case QDF_PROTO_ICMPV6_RES:
	case QDF_PROTO_ICMPV6_RS:
	case QDF_PROTO_ICMPV6_RA:
	case QDF_PROTO_ICMPV6_NS:
	case QDF_PROTO_ICMPV6_NA:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		if (buf_len >= WMA_IPV6_PKT_INFO_GET_MIN_LEN) {
			pkt_len = (uint16_t)(*(uint16_t *)(data +
				IPV6_PKT_LEN_OFFSET));
			seq_num = (uint16_t)(*(uint16_t *)(data +
				ICMPV6_SEQ_NUM_OFFSET));
			WMA_LOGD("Pkt_len: %u, Seq_num: %u",
				ani_cpu_to_be16(pkt_len),
				ani_cpu_to_be16(seq_num));
		}
		break;

	case QDF_PROTO_IPV4_UDP:
	case QDF_PROTO_IPV4_TCP:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		if (buf_len >= WMA_IPV4_PKT_INFO_GET_MIN_LEN) {
			pkt_len = (uint16_t)(*(uint16_t *)(data +
				IPV4_PKT_LEN_OFFSET));
			ip_addr = (char *)(data + IPV4_SRC_ADDR_OFFSET);
			WMA_LOGD("src addr %d:%d:%d:%d", ip_addr[0], ip_addr[1],
				ip_addr[2], ip_addr[3]);
			ip_addr = (char *)(data + IPV4_DST_ADDR_OFFSET);
			WMA_LOGD("dst addr %d:%d:%d:%d", ip_addr[0], ip_addr[1],
				ip_addr[2], ip_addr[3]);
			src_port = (uint16_t)(*(uint16_t *)(data +
				IPV4_SRC_PORT_OFFSET));
			dst_port = (uint16_t)(*(uint16_t *)(data +
				IPV4_DST_PORT_OFFSET));
			WMA_LOGD("Pkt_len: %u",
				ani_cpu_to_be16(pkt_len));
			WMA_LOGI("src_port: %u, dst_port: %u",
				ani_cpu_to_be16(src_port),
				ani_cpu_to_be16(dst_port));
			if (proto_subtype == QDF_PROTO_IPV4_TCP) {
				tcp_seq_num = (uint32_t)(*(uint32_t *)(data +
					IPV4_TCP_SEQ_NUM_OFFSET));
				WMA_LOGD("TCP_seq_num: %u",
					ani_cpu_to_be16(tcp_seq_num));
			}
		}
		break;

	case QDF_PROTO_IPV6_UDP:
	case QDF_PROTO_IPV6_TCP:
		WMA_LOGI("WOW Wakeup: %s rcvd",
			wma_pkt_proto_subtype_to_string(proto_subtype));
		if (buf_len >= WMA_IPV6_PKT_INFO_GET_MIN_LEN) {
			pkt_len = (uint16_t)(*(uint16_t *)(data +
				IPV6_PKT_LEN_OFFSET));
			ip_addr = (char *)(data + IPV6_SRC_ADDR_OFFSET);
			WMA_LOGD("src addr "IPV6_ADDR_STR, ip_addr[0],
				ip_addr[1], ip_addr[2], ip_addr[3], ip_addr[4],
				ip_addr[5], ip_addr[6], ip_addr[7], ip_addr[8],
				ip_addr[9], ip_addr[10], ip_addr[11],
				ip_addr[12], ip_addr[13], ip_addr[14],
				ip_addr[15]);
			ip_addr = (char *)(data + IPV6_DST_ADDR_OFFSET);
			WMA_LOGD("dst addr "IPV6_ADDR_STR, ip_addr[0],
				ip_addr[1], ip_addr[2], ip_addr[3], ip_addr[4],
				ip_addr[5], ip_addr[6], ip_addr[7], ip_addr[8],
				ip_addr[9], ip_addr[10], ip_addr[11],
				ip_addr[12], ip_addr[13], ip_addr[14],
				ip_addr[15]);
			src_port = (uint16_t)(*(uint16_t *)(data +
				IPV6_SRC_PORT_OFFSET));
			dst_port = (uint16_t)(*(uint16_t *)(data +
				IPV6_DST_PORT_OFFSET));
			WMA_LOGD("Pkt_len: %u",
				ani_cpu_to_be16(pkt_len));
			WMA_LOGI("src_port: %u, dst_port: %u",
				ani_cpu_to_be16(src_port),
				ani_cpu_to_be16(dst_port));
			if (proto_subtype == QDF_PROTO_IPV6_TCP) {
				tcp_seq_num = (uint32_t)(*(uint32_t *)(data +
					IPV6_TCP_SEQ_NUM_OFFSET));
				WMA_LOGD("TCP_seq_num: %u",
					ani_cpu_to_be16(tcp_seq_num));
			}
		}
		break;

	default:
end:
		WMA_LOGD("wow_buf_pkt_len: %u", buf_len);
		break;
	}
}

/**
 * wma_wow_dump_mgmt_buffer() - API to parse data buffer for mgmt.
 *    packet that resulted in WOW wakeup.
 * @wow_packet_buffer: Pointer to data buffer
 * @buf_len: length of data buffer
 *
 * This function parses the data buffer received (802.11 header)
 * to get informaton like src mac addr, dst mac addr, seq_num,
 * frag_num, etc.
 *
 * Return: void
 */
static void wma_wow_dump_mgmt_buffer(uint8_t *wow_packet_buffer,
			uint32_t buf_len)
{
	struct ieee80211_frame_addr4 *wh;

	WMA_LOGD("wow_buf_pkt_len: %u", buf_len);
	wh = (struct ieee80211_frame_addr4 *)
		(wow_packet_buffer + 4);
	if (buf_len >= sizeof(struct ieee80211_frame)) {
		uint8_t to_from_ds, frag_num;
		uint32_t seq_num;

		WMA_LOGE("RA: " MAC_ADDRESS_STR " TA: " MAC_ADDRESS_STR,
			MAC_ADDR_ARRAY(wh->i_addr1),
			MAC_ADDR_ARRAY(wh->i_addr2));

		WMA_LOGE("TO_DS: %u, FROM_DS: %u",
			wh->i_fc[1] & IEEE80211_FC1_DIR_TODS,
			wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS);

		to_from_ds = wh->i_fc[1] & IEEE80211_FC1_DIR_DSTODS;

		switch (to_from_ds) {
		case IEEE80211_NO_DS:
			WMA_LOGE("BSSID: " MAC_ADDRESS_STR,
				MAC_ADDR_ARRAY(wh->i_addr3));
			break;
		case IEEE80211_TO_DS:
			WMA_LOGE("DA: " MAC_ADDRESS_STR,
				MAC_ADDR_ARRAY(wh->i_addr3));
			break;
		case IEEE80211_FROM_DS:
			WMA_LOGE("SA: " MAC_ADDRESS_STR,
				MAC_ADDR_ARRAY(wh->i_addr3));
			break;
		case IEEE80211_DS_TO_DS:
			if (buf_len >= sizeof(struct ieee80211_frame_addr4))
				WMA_LOGE("DA: " MAC_ADDRESS_STR " SA: "
					MAC_ADDRESS_STR,
					MAC_ADDR_ARRAY(wh->i_addr3),
					MAC_ADDR_ARRAY(wh->i_addr4));
			break;
		}

		seq_num = (((*(uint16_t *)wh->i_seq) &
				IEEE80211_SEQ_SEQ_MASK) >>
				IEEE80211_SEQ_SEQ_SHIFT);
		frag_num = (((*(uint16_t *)wh->i_seq) &
				IEEE80211_SEQ_FRAG_MASK) >>
				IEEE80211_SEQ_FRAG_SHIFT);

		WMA_LOGE("SEQ_NUM: %u, FRAG_NUM: %u",
				seq_num, frag_num);
	} else {
		WMA_LOGE("Insufficient buffer length for mgmt. packet");
	}
}

/**
 * wma_wow_get_wakelock_ms() - return the wakelock duration
 *        for some mgmt packets received.
 * @wake_reason: wow wakeup reason
 *
 * This function returns the wakelock duration for some mgmt packets
 * received while in wow suspend.
 *
 * Return: wakelock duration in ms
 */
static uint32_t wma_wow_get_wakelock_ms(int wake_reason)
{
	switch (wake_reason) {
	case WOW_REASON_AUTH_REQ_RECV:
		return WMA_AUTH_REQ_RECV_WAKE_LOCK_TIMEOUT;
	case WOW_REASON_ASSOC_REQ_RECV:
		return WMA_ASSOC_REQ_RECV_WAKE_LOCK_DURATION;
	case WOW_REASON_DEAUTH_RECVD:
		return WMA_DEAUTH_RECV_WAKE_LOCK_DURATION;
	case WOW_REASON_DISASSOC_RECVD:
		return WMA_DISASSOC_RECV_WAKE_LOCK_DURATION;
	case WOW_REASON_AP_ASSOC_LOST:
		return WMA_BMISS_EVENT_WAKE_LOCK_DURATION;
#ifdef FEATURE_WLAN_AUTO_SHUTDOWN
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		return WMA_AUTO_SHUTDOWN_WAKE_LOCK_DURATION;
#endif
	case WOW_REASON_ROAM_HO:
		return WMA_ROAM_HO_WAKE_LOCK_DURATION;
	}

	return 0;
}

/**
 * wma_wow_get_wakelock() - return the wakelock
 *        for some mgmt packets received.
 * @wma_handle: wma handle
 * @wake_reason: wow wakeup reason
 *
 * This function returns the wakelock for some mgmt packets
 * received while in wow suspend.
 *
 * Return: wakelock
 */
static qdf_wake_lock_t *wma_wow_get_wakelock(tp_wma_handle wma_handle,
		int wake_reason)
{

	switch (wake_reason) {
	case WOW_REASON_AUTH_REQ_RECV:
		return &wma_handle->wow_auth_req_wl;
	case WOW_REASON_ASSOC_REQ_RECV:
		return &wma_handle->wow_assoc_req_wl;
	case WOW_REASON_DEAUTH_RECVD:
		return &wma_handle->wow_deauth_rec_wl;
	case WOW_REASON_DISASSOC_RECVD:
		return &wma_handle->wow_disassoc_rec_wl;
	case WOW_REASON_AP_ASSOC_LOST:
		return &wma_handle->wow_ap_assoc_lost_wl;
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		return &wma_handle->wow_auto_shutdown_wl;
	case WOW_REASON_ROAM_HO:
		return &wma_handle->roam_ho_wl;
	default:
		return NULL;
	}

}

/**
 * wma_wow_ap_lost_helper() - helper function to handle WOW_REASON_AP_ASSOC_LOST
 * reason code and retrieve RSSI from the event.
 * @wma: Pointer to wma handle
 * @param: WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs buffer pointer
 *
 * Return: none
 */
static void wma_wow_ap_lost_helper(tp_wma_handle wma, void *param)
{
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *param_buf;
	WOW_EVENT_INFO_fixed_param *wake_info;
	WMI_ROAM_EVENTID_param_tlvs event_param;
	wmi_roam_event_fixed_param *roam_event;
	u_int32_t wow_buf_pkt_len = 0;

	param_buf = (WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *) param;
	wake_info = param_buf->fixed_param;
	WMA_LOGA("%s: Beacon miss indication on vdev %d",
		__func__, wake_info->vdev_id);

	if (NULL == param_buf->wow_packet_buffer) {
		WMA_LOGE("%s: invalid wow packet buffer", __func__);
		goto exit_handler;
	}

	qdf_mem_copy((u_int8_t *) &wow_buf_pkt_len,
		param_buf->wow_packet_buffer, 4);
	WMA_LOGD("wow_packet_buffer dump");
	qdf_trace_hex_dump(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_DEBUG,
		param_buf->wow_packet_buffer, wow_buf_pkt_len);
	if (wow_buf_pkt_len >= sizeof(event_param)) {
		roam_event = (wmi_roam_event_fixed_param *)
			(param_buf->wow_packet_buffer + 4);
		wma_beacon_miss_handler(wma, wake_info->vdev_id,
			roam_event->rssi);
		return;
	}

exit_handler:
	/* in the case that no RSSI is available from the event */
	WMA_LOGE("%s: rssi is not available from wow_packet_buffer", __func__);
	wma_beacon_miss_handler(wma, wake_info->vdev_id, 0);
}

static const char *wma_vdev_type_str(uint32_t vdev_type)
{
	switch (vdev_type) {
	case WMI_VDEV_TYPE_AP:
		return "AP";
	case WMI_VDEV_TYPE_STA:
		return "STA";
	case WMI_VDEV_TYPE_IBSS:
		return "IBSS";
	case WMI_VDEV_TYPE_MONITOR:
		return "MONITOR";
	case WMI_VDEV_TYPE_NAN:
		return "NAN";
	case WMI_VDEV_TYPE_OCB:
		return "OCB";
	case WMI_VDEV_TYPE_NDI:
		return "NDI";
	default:
		return "unknown";
	}
}

#ifdef FEATURE_WLAN_D0WOW
 /**
 * wma_d0_wow_disable_ack_event() - wakeup host event handler
 * @handle: wma handle
 * @event: event data
 * @len: buffer length
 *
 * Handler to catch D0-WOW disable ACK event.  This event will have
 * reason why the firmware has woken the host.
 * This is for backward compatible with cld2.0.
 *
 * Return: 0 for success or error
 */
int wma_d0_wow_disable_ack_event(void *handle, u_int8_t *event,
				u_int32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	WMI_D0_WOW_DISABLE_ACK_EVENTID_param_tlvs *param_buf;
	wmi_d0_wow_disable_ack_event_fixed_param *resp_data;

	param_buf = (WMI_D0_WOW_DISABLE_ACK_EVENTID_param_tlvs *)event;
	if (!param_buf) {
		WMA_LOGE("Invalid D0-WOW disable ACK event buffer!");
		return -EINVAL;
	}

	resp_data = param_buf->fixed_param;
	qdf_event_set(&wma->wma_resume_event);
	WMA_LOGD("Received D0-WOW disable ACK");

	return 0;
}
#else
int wma_d0_wow_disable_ack_event(void *handle, u_int8_t *event,
				u_int32_t len)
{
	return 0;
}
#endif

/**
 * wma_wow_wakeup_host_event() - wakeup host event handler
 * @handle: wma handle
 * @event: event data
 * @len: buffer length
 *
 * Handler to catch wow wakeup host event. This event will have
 * reason why the firmware has woken the host.
 *
 * Return: 0 for success or error
 */
int wma_wow_wakeup_host_event(void *handle, uint8_t *event,
			      uint32_t len)
{
	uint8_t *bssid;
	uint8_t peer_id;
	ol_txrx_peer_handle peer;
	ol_txrx_pdev_handle pdev;
	tpDeleteStaContext del_sta_ctx;
	tp_wma_handle wma = (tp_wma_handle) handle;
	struct wma_txrx_node *wma_vdev = NULL;
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *param_buf;
	WOW_EVENT_INFO_fixed_param *wake_info;
	uint32_t wakelock_duration;
	void *wmi_cmd_struct_ptr = NULL;
	uint32_t tlv_hdr, tag, wow_buf_pkt_len = 0, event_id = 0;
	uint8_t *wow_buf_data = NULL;
	int tlv_ok_status;

	pdev = cds_get_context(QDF_MODULE_ID_TXRX);
	if (!pdev) {
		WMA_LOGE("Invalid pdev");
		return -EINVAL;
	}

	param_buf = (WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *) event;
	if (!param_buf) {
		WMA_LOGE("Invalid wow wakeup host event buf");
		return -EINVAL;
	}

	wake_info = param_buf->fixed_param;
	bssid = wma->interfaces[wake_info->vdev_id].bssid;
	peer = ol_txrx_find_peer_by_addr(pdev, bssid, &peer_id);

	/* unspecified means apps-side wakeup, so there won't be a vdev */
	if (wake_info->wake_reason != WOW_REASON_UNSPECIFIED) {
		if (wake_info->vdev_id >= wma->max_bssid) {
			WMA_LOGE("%s: received invalid vdev_id %d",
				 __func__, wake_info->vdev_id);
			return -EINVAL;
		}
		wma_vdev = &wma->interfaces[wake_info->vdev_id];
		WMA_LOGA("WLAN triggered wakeup: %s (%d), vdev: %d (%s)",
			 wma_wow_wake_reason_str(wake_info->wake_reason),
			 wake_info->wake_reason,
			 wake_info->vdev_id,
			 wma_vdev_type_str(wma_vdev->type));
		qdf_wow_wakeup_host_event(wake_info->wake_reason);
		qdf_wma_wow_wakeup_stats_event();
	} else if (!wmi_get_runtime_pm_inprogress(wma->wmi_handle)) {
		WMA_LOGA("Non-WLAN triggered wakeup: %s (%d)",
			 wma_wow_wake_reason_str(wake_info->wake_reason),
			 wake_info->wake_reason);
		qdf_wow_wakeup_host_event(wake_info->wake_reason);
		qdf_wma_wow_wakeup_stats_event();
	}

	qdf_event_set(&wma->wma_resume_event);

	if (param_buf->wow_packet_buffer) {
		/*
		 * In case of wow_packet_buffer, first 4 bytes is the length.
		 * Following the length is the actual buffer.
		 */
		if (param_buf->num_wow_packet_buffer <= 4) {
			WMA_LOGE("Invalid wow packet buffer from firmware %u",
				  param_buf->num_wow_packet_buffer);
			return -EINVAL;
		}
		wow_buf_pkt_len = *(uint32_t *)param_buf->wow_packet_buffer;
		if (wow_buf_pkt_len > (param_buf->num_wow_packet_buffer - 4)) {
			WMA_LOGE("Invalid wow buf pkt len from firmware, wow_buf_pkt_len: %u, num_wow_packet_buffer: %u",
				 wow_buf_pkt_len,
				 param_buf->num_wow_packet_buffer);
			return -EINVAL;
		}
	}

	if (param_buf->wow_packet_buffer &&
	    tlv_check_required(wake_info->wake_reason)) {

		tlv_hdr = WMITLV_GET_HDR(
				(uint8_t *)param_buf->wow_packet_buffer + 4);

		tag = WMITLV_GET_TLVTAG(tlv_hdr);
		event_id = wow_get_wmi_eventid(wake_info->wake_reason, tag);
		if (!event_id) {
			WMA_LOGE(FL("Unable to find matching ID"));
			return -EINVAL;
		}

		tlv_ok_status = wmitlv_check_and_pad_event_tlvs(
				    handle, param_buf->wow_packet_buffer + 4,
				    wow_buf_pkt_len, event_id,
				    &wmi_cmd_struct_ptr);

		if (tlv_ok_status != 0) {
			WMA_LOGE(FL("Invalid TLVs, Length:%d event_id:%d status: %d"),
				 wow_buf_pkt_len, event_id, tlv_ok_status);
			return -EINVAL;
		}
	}

	switch (wake_info->wake_reason) {
	case WOW_REASON_AUTH_REQ_RECV:
	case WOW_REASON_ASSOC_REQ_RECV:
	case WOW_REASON_DEAUTH_RECVD:
	case WOW_REASON_DISASSOC_RECVD:
	case WOW_REASON_ASSOC_RES_RECV:
	case WOW_REASON_REASSOC_REQ_RECV:
	case WOW_REASON_REASSOC_RES_RECV:
	case WOW_REASON_BEACON_RECV:
	case WOW_REASON_ACTION_FRAME_RECV:
		if (param_buf->wow_packet_buffer) {
			if (wow_buf_pkt_len)
				wma_wow_dump_mgmt_buffer(
					param_buf->wow_packet_buffer,
					wow_buf_pkt_len);
			else
				WMA_LOGE("wow packet buffer is empty");
		} else {
			WMA_LOGE("No wow packet buffer present");
		}
		break;

	case WOW_REASON_AP_ASSOC_LOST:
		wma_wow_ap_lost_helper(wma, param_buf);
		break;
#ifdef FEATURE_WLAN_AUTO_SHUTDOWN
	case WOW_REASON_HOST_AUTO_SHUTDOWN:
		WMA_LOGA("Received WOW Auto Shutdown trigger in suspend");
		if (wma_post_auto_shutdown_msg())
			return -EINVAL;
		break;
#endif /* FEATURE_WLAN_AUTO_SHUTDOWN */
#ifdef FEATURE_WLAN_SCAN_PNO
	case WOW_REASON_NLOD:
		if (wma_vdev) {
			WMA_LOGD("NLO match happened");
			wma_vdev->nlo_match_evt_received = true;
			cds_host_diag_log_work(&wma->pno_wake_lock,
					WMA_PNO_MATCH_WAKE_LOCK_TIMEOUT,
					WIFI_POWER_EVENT_WAKELOCK_PNO);
			qdf_wake_lock_timeout_acquire(&wma->pno_wake_lock,
					WMA_PNO_MATCH_WAKE_LOCK_TIMEOUT);
		}
		break;

	case WOW_REASON_NLO_SCAN_COMPLETE:
		WMA_LOGD("Host woken up due to pno scan complete reason");
		if (param_buf->wow_packet_buffer)
			wma_nlo_scan_cmp_evt_handler(handle,
					wmi_cmd_struct_ptr, wow_buf_pkt_len);
		else
			WMA_LOGD("No wow_packet_buffer present");
		break;
#endif /* FEATURE_WLAN_SCAN_PNO */

	case WOW_REASON_CSA_EVENT:
		WMA_LOGD("Host woken up because of CSA IE");
		wma_csa_offload_handler(handle, wmi_cmd_struct_ptr,
					wow_buf_pkt_len);
		break;

#ifdef FEATURE_WLAN_LPHB
	case WOW_REASON_WLAN_HB:
		wma_lphb_handler(wma, (uint8_t *) param_buf->hb_indevt);
		break;
#endif /* FEATURE_WLAN_LPHB */

	case WOW_REASON_HTT_EVENT:
		break;

	case WOW_REASON_BPF_ALLOW:
	case WOW_REASON_PATTERN_MATCH_FOUND:
#ifdef FEATURE_WLAN_RA_FILTERING
	case WOW_REASON_RA_MATCH:
#endif /* FEATURE_WLAN_RA_FILTERING */
	case WOW_REASON_RECV_MAGIC_PATTERN:
	case WOW_REASON_PACKET_FILTER_MATCH:
		WMA_LOGD("Wake up for Rx packet, dump starting from ethernet hdr");
		if (!param_buf->wow_packet_buffer) {
			WMA_LOGE("No wow packet buffer present");
			break;
		}

		if (wow_buf_pkt_len == 0) {
			WMA_LOGE("wow packet buffer is empty");
			break;
		}

		wow_buf_data = (uint8_t *)(param_buf->wow_packet_buffer + 4);
		qdf_trace_hex_dump(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_DEBUG,
				   wow_buf_data, wow_buf_pkt_len);
		wma_wow_parse_data_pkt_buffer(wow_buf_data, wow_buf_pkt_len);

		break;

	case WOW_REASON_LOW_RSSI:
	case WOW_REASON_ROAM_HO:
		/*
		 * WOW_REASON_LOW_RSSI is used for following roaming events -
		 * WMI_ROAM_REASON_BETTER_AP, WMI_ROAM_REASON_BMISS,
		 * WMI_ROAM_REASON_SUITABLE_AP will be handled by
		 * wma_roam_event_callback().
		 * WOW_REASON_ROAM_HO is associated with
		 * WMI_ROAM_REASON_HO_FAILED event and it will be handled by
		 * wma_roam_event_callback().
		 */
		wma_peer_debug_log(wake_info->vdev_id,
				DEBUG_WOW_ROAM_EVENT, DEBUG_INVALID_PEER_ID,
				NULL, NULL, wake_info->wake_reason,
				wow_buf_pkt_len);
		WMA_LOGD("Host woken up because of roam event");
		if (param_buf->wow_packet_buffer) {
			/* Roam event is embedded in wow_packet_buffer */
			WMA_LOGD("wow_packet_buffer dump");
			qdf_trace_hex_dump(QDF_MODULE_ID_WMA,
					   QDF_TRACE_LEVEL_DEBUG,
					   param_buf->wow_packet_buffer,
					   wow_buf_pkt_len);
			wma_roam_event_callback(handle, wmi_cmd_struct_ptr,
						wow_buf_pkt_len);
		} else {
			/*
			 * No wow_packet_buffer means a better AP beacon
			 * will follow in a later event.
			 */
			WMA_LOGD("Host woken up because of better AP beacon");
		}
		break;
	case WOW_REASON_CLIENT_KICKOUT_EVENT:
		WMA_LOGD("Host woken up because of sta_kickout event");
		if (param_buf->wow_packet_buffer) {
			WMA_LOGD("wow_packet_buffer dump");
			qdf_trace_hex_dump(QDF_MODULE_ID_WMA,
				QDF_TRACE_LEVEL_DEBUG,
				param_buf->wow_packet_buffer, wow_buf_pkt_len);
			wma_peer_sta_kickout_event_handler(handle,
				wmi_cmd_struct_ptr, wow_buf_pkt_len);
		} else {
		    WMA_LOGD("No wow_packet_buffer present");
		}
		break;
#ifdef FEATURE_WLAN_EXTSCAN
	case WOW_REASON_EXTSCAN:
		WMA_LOGD("Host woken up because of extscan reason");
		if (param_buf->wow_packet_buffer)
			wma_extscan_wow_event_callback(handle,
				wmi_cmd_struct_ptr, wow_buf_pkt_len);
		else
			WMA_LOGE("wow_packet_buffer is empty");
		break;
#endif
	case WOW_REASON_RSSI_BREACH_EVENT:
		WMA_LOGD("Host woken up because of rssi breach reason");
		/* rssi breach event is embedded in wow_packet_buffer */
		if (param_buf->wow_packet_buffer)
			wma_rssi_breached_event_handler(handle,
				wmi_cmd_struct_ptr, wow_buf_pkt_len);
		else
		    WMA_LOGD("No wow_packet_buffer present");
		break;
	case WOW_REASON_NAN_EVENT:
		WMA_LOGA("Host woken up due to NAN event reason");
		wma_nan_rsp_event_handler(handle,
				wmi_cmd_struct_ptr, wow_buf_pkt_len);
		break;
	case WOW_REASON_NAN_DATA:
		WMA_LOGD(FL("Host woken up for NAN data path event from FW"));
		if (param_buf->wow_packet_buffer) {
			wma_ndp_wow_event_callback(handle, wmi_cmd_struct_ptr,
						   wow_buf_pkt_len, event_id);
		} else {
			WMA_LOGE(FL("wow_packet_buffer is empty"));
		}
		break;
	case WOW_REASON_OEM_RESPONSE_EVENT:
		/*
		 * Actual OEM Response event will follow after this
		 * WOW Wakeup event
		 */
		WMA_LOGD(FL("Host woken up for OEM Response event"));
		break;
#ifdef FEATURE_WLAN_TDLS
	case WOW_REASON_TDLS_CONN_TRACKER_EVENT:
		WMA_LOGD("Host woken up because of TDLS event");
		if (param_buf->wow_packet_buffer)
			wma_tdls_event_handler(handle,
				wmi_cmd_struct_ptr, wow_buf_pkt_len);
		else
			WMA_LOGD("No wow_packet_buffer present");
		break;
#endif
	case WOW_REASON_CHIP_POWER_FAILURE_DETECT:
		/* Just update stats and exit */
		WMA_LOGD("Host woken up because of chip power save failure");
		break;
	case WOW_REASON_TIMER_INTR_RECV:
		/*
		 * Right now firmware is not returning any cookie host has
		 * programmed. So do not check for cookie.
		 */
		WMA_LOGE("WOW_REASON_TIMER_INTR_RECV received, indicating key exchange did not finish. Initiate disconnect");

		del_sta_ctx = (tpDeleteStaContext) qdf_mem_malloc(sizeof(*del_sta_ctx));
		if (!del_sta_ctx) {
			WMA_LOGE("%s: mem alloc failed ", __func__);
			break;
		}
		del_sta_ctx->is_tdls = false;
		del_sta_ctx->vdev_id = wake_info->vdev_id;
		del_sta_ctx->staId = peer_id;
		qdf_mem_copy(del_sta_ctx->addr2, bssid, IEEE80211_ADDR_LEN);
		qdf_mem_copy(del_sta_ctx->bssId, bssid, IEEE80211_ADDR_LEN);
		del_sta_ctx->reasonCode = HAL_DEL_STA_REASON_CODE_KEEP_ALIVE;
		wma_send_msg(wma, SIR_LIM_DELETE_STA_CONTEXT_IND,
			     (void *)del_sta_ctx, 0);
		break;
	default:
		break;
	}

	/* Log wake reason at appropriate (global/vdev) level  */
	if (wake_info->wake_reason == WOW_REASON_UNSPECIFIED)
		wma->wow_unspecified_wake_count++;
	else if (wma_vdev)
		wma_inc_wow_stats(&wma_vdev->wow_stats,
				  wow_buf_data,
				  wow_buf_data ? wow_buf_pkt_len : 0,
				  wake_info->wake_reason);
	else
		WMA_LOGE("Vdev is NULL, but wake reason is vdev related");

	wakelock_duration = wma_wow_get_wakelock_ms(wake_info->wake_reason);
	if (wakelock_duration) {
		qdf_wake_lock_t *wake_lock = wma_wow_get_wakelock(wma,
						wake_info->wake_reason);
		if (wake_lock) {
			cds_host_diag_log_work(wake_lock,
					       wakelock_duration,
					       WIFI_POWER_EVENT_WAKELOCK_WOW);
			qdf_wake_lock_timeout_acquire(wake_lock,
						      wakelock_duration);
			WMA_LOGA("Holding %d msec wake_lock",
					wakelock_duration);
		}
	}

	if (wmi_cmd_struct_ptr)
		wmitlv_free_allocated_event_tlvs(event_id, &wmi_cmd_struct_ptr);

	return 0;
}

/**
 * wma_pdev_resume_event_handler() - PDEV resume event handler
 * @handle: wma handle
 * @event: event data
 * @len: buffer length
 *
 * Return: 0 for success or error
 */
int wma_pdev_resume_event_handler(void *handle, uint8_t *event, uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;

	WMA_LOGA("Received PDEV resume event");

	qdf_event_set(&wma->wma_resume_event);

	return 0;
}
/**
 * wma_set_wow_bus_suspend() - set suspend flag
 * @wma: wma handle
 * @val: value
 *
 * Return: none
 */
static inline void wma_set_wow_bus_suspend(tp_wma_handle wma, int val)
{
	qdf_atomic_set(&wma->is_wow_bus_suspended, val);
	wmi_set_is_wow_bus_suspended(wma->wmi_handle, val);
}

/**
 * wma_add_wow_wakeup_event() -  Configures wow wakeup events.
 * @wma: wma handle
 * @vdev_id: vdev id
 * @bitmap: Event bitmap
 * @enable: enable/disable
 *
 * Return: QDF status
 */
QDF_STATUS wma_add_wow_wakeup_event(tp_wma_handle wma,
					uint32_t vdev_id,
					uint32_t *bitmap,
					bool enable)
{
	int ret;

	ret = wmi_unified_add_wow_wakeup_event_cmd(wma->wmi_handle, vdev_id,
			bitmap, enable);
	if (ret) {
		WMA_LOGE("Failed to config wow wakeup event");
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_send_wow_patterns_to_fw() - Sends WOW patterns to FW.
 * @wma: wma handle
 * @vdev_id: vdev id
 * @ptrn_id: pattern id
 * @ptrn: pattern
 * @ptrn_len: pattern length
 * @ptrn_offset: pattern offset
 * @mask: mask
 * @mask_len: mask length
 * @user: true for user configured pattern and false for default pattern
 *
 * Return: QDF status
 */
static QDF_STATUS wma_send_wow_patterns_to_fw(tp_wma_handle wma,
				uint8_t vdev_id, uint8_t ptrn_id,
				const uint8_t *ptrn, uint8_t ptrn_len,
				uint8_t ptrn_offset, const uint8_t *mask,
				uint8_t mask_len, bool user)
{
	struct wma_txrx_node *iface;
	int ret;

	iface = &wma->interfaces[vdev_id];
	ret = wmi_unified_wow_patterns_to_fw_cmd(wma->wmi_handle,
			    vdev_id, ptrn_id, ptrn,
				ptrn_len, ptrn_offset, mask,
				mask_len, user, 0);
	if (ret) {
		if (!user)
			wma_decrement_wow_default_ptrn(wma, vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	if (user)
		wma_increment_wow_user_ptrn(wma, vdev_id);

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_wow_ap() - set WOW patterns in ap mode
 * @wma: wma handle
 * @vdev_id: vdev id
 *
 * Configures default WOW pattern for the given vdev_id which is in AP mode.
 *
 * Return: QDF status
 */
static QDF_STATUS wma_wow_ap(tp_wma_handle wma, uint8_t vdev_id)
{
	QDF_STATUS ret;
	uint8_t arp_offset = 20;
	uint8_t mac_mask[IEEE80211_ADDR_LEN];

	/*
	 * Setup unicast pkt pattern
	 * WoW pattern id should be unique for each vdev
	 * WoW pattern id can be same on 2 different VDEVs
	 */
	qdf_mem_set(&mac_mask, IEEE80211_ADDR_LEN, 0xFF);
	ret = wma_send_wow_patterns_to_fw(wma, vdev_id,
			wma_get_and_increment_wow_default_ptrn(wma, vdev_id),
			wma->interfaces[vdev_id].addr,
			IEEE80211_ADDR_LEN, 0, mac_mask,
			IEEE80211_ADDR_LEN, false);
	if (ret != QDF_STATUS_SUCCESS) {
		WMA_LOGE("Failed to add WOW unicast pattern ret %d", ret);
		return ret;
	}

	/*
	 * Setup all ARP pkt pattern. This is dummy pattern hence the length
	 * is zero. Pattern ID should be unique per vdev.
	 */
	ret = wma_send_wow_patterns_to_fw(wma, vdev_id,
			wma_get_and_increment_wow_default_ptrn(wma, vdev_id),
			arp_ptrn, 0, arp_offset, arp_mask, 0, false);
	if (ret != QDF_STATUS_SUCCESS) {
		WMA_LOGE("Failed to add WOW ARP pattern ret %d", ret);
		return ret;
	}

	return ret;
}

/**
 * wma_configure_wow_ssdp() - API to configure WoW SSDP
 * @wma: WMA Handle
 * @vdev_id: Vdev Id
 *
 * API to configure SSDP pattern as WoW pattern
 *
 * Return: Success/Failure
 */
static QDF_STATUS wma_configure_wow_ssdp(tp_wma_handle wma, uint8_t vdev_id)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint8_t discvr_offset = 30;

	/*
	 * WoW pattern ID should be unique for each vdev
	 * Different WoW patterns can use same pattern ID
	 */
	 status = wma_send_wow_patterns_to_fw(wma, vdev_id,
			wma_get_and_increment_wow_default_ptrn(wma, vdev_id),
			discvr_ptrn, sizeof(discvr_ptrn), discvr_offset,
			discvr_mask, sizeof(discvr_ptrn), false);

	if (status != QDF_STATUS_SUCCESS)
		WMA_LOGE("Failed to add WOW mDNS/SSDP/LLMNR pattern");

	return status;
}

/**
 * wma_configure_mc_ssdp() - API to configure SSDP address as MC list
 * @wma: WMA Handle
 * @vdev_id: Vdev Id
 *
 * SSDP address 239.255.255.250 is converted to Multicast Mac address
 * and configure it to FW. Firmware will apply this pattern on the incoming
 * packets to filter them out during chatter/wow mode.
 *
 * Return: Success/Failure
 */
static QDF_STATUS wma_configure_mc_ssdp(tp_wma_handle wma, uint8_t vdev_id)
{
	WMI_SET_MCASTBCAST_FILTER_CMD_fixed_param *cmd;
	wmi_buf_t buf;

	const tSirMacAddr ssdp_addr = {0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa};
	int ret;
	WMI_SET_MCASTBCAST_FILTER_CMD_fixed_param fixed_param;
	uint32_t tag =
		WMITLV_TAG_STRUC_WMI_SET_MCASTBCAST_FILTER_CMD_fixed_param;

	buf = wmi_buf_alloc(wma->wmi_handle, sizeof(*cmd));
	if (!buf) {
		WMA_LOGE("%s No Memory for MC address", __func__);
		return QDF_STATUS_E_NOMEM;
	}

	cmd = (WMI_SET_MCASTBCAST_FILTER_CMD_fixed_param *) wmi_buf_data(buf);

	WMITLV_SET_HDR(&cmd->tlv_header, tag,
		       WMITLV_GET_STRUCT_TLVLEN(fixed_param));

	cmd->action = WMI_MCAST_FILTER_SET;
	cmd->vdev_id = vdev_id;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(ssdp_addr, &cmd->mcastbdcastaddr);
	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, sizeof(*cmd),
				   WMI_SET_MCASTBCAST_FILTER_CMDID);
	if (ret != QDF_STATUS_SUCCESS) {
		WMA_LOGE("%s Failed to configure FW with SSDP MC address",
			 __func__);
		wmi_buf_free(buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_configure_ssdp() - API to Configure SSDP pattern to FW
 * @wma: WMA Handle
 * @vdev_id: VDEV ID
 *
 * Setup multicast pattern for mDNS 224.0.0.251, SSDP 239.255.255.250 and LLMNR
 * 224.0.0.252
 *
 * Return: Success/Failure.
 */
static QDF_STATUS wma_configure_ssdp(tp_wma_handle wma, uint8_t vdev_id)
{
	if (!wma->ssdp) {
		WMA_LOGD("mDNS, SSDP, LLMNR patterns are disabled from ini");
		return QDF_STATUS_SUCCESS;
	}

	WMA_LOGD("%s, enable_mc_list:%d", __func__, wma->enable_mc_list);

	if (wma->enable_mc_list)
		return wma_configure_mc_ssdp(wma, vdev_id);

	return wma_configure_wow_ssdp(wma, vdev_id);
}

/**
 * set_action_id_drop_pattern_for_spec_mgmt() - Set action id of action
 * frames for spectrum mgmt frames to be droppped in fw.
 *
 * @action_id_per_category: Pointer to action id bitmaps.
 */
static void set_action_id_drop_pattern_for_spec_mgmt(
					uint32_t *action_id_per_category)
{
	action_id_per_category[SIR_MAC_ACTION_SPECTRUM_MGMT]
				= DROP_SPEC_MGMT_ACTION_FRAME_BITMAP;
}

/**
 * wma_register_action_frame_patterns() - register action frame map to fw
 * @handle: Pointer to wma handle
 * @vdev_id: VDEV ID
 *
 * This is called to push action frames wow patterns from local
 * cache to firmware.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wma_register_action_frame_patterns(WMA_HANDLE handle,
						uint8_t vdev_id)
{
	tp_wma_handle wma = handle;
	struct action_wakeup_set_param *cmd;
	int32_t err;
	int i = 0;

	cmd = qdf_mem_malloc(sizeof(*cmd));
	if (!cmd) {
		WMA_LOGE("failed to alloc memory");
		return QDF_STATUS_E_FAILURE;
	}

	cmd->vdev_id = vdev_id;
	cmd->operation = WOW_ACTION_WAKEUP_OPERATION_SET;

	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP0;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP1;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP2;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP3;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP4;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP5;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP6;
	cmd->action_category_map[i++] = ALLOWED_ACTION_FRAMES_BITMAP7;

	set_action_id_drop_pattern_for_spec_mgmt(cmd->action_per_category);
	cmd->action_per_category[SIR_MAC_ACTION_PUBLIC_USAGE] =
			DROP_PUBLIC_ACTION_FRAME_BITMAP;

	for (i = 0; i < WMI_SUPPORTED_ACTION_CATEGORY_ELE_LIST; i++) {
		if (i < ALLOWED_ACTION_FRAME_MAP_WORDS)
			WMA_LOGD("%s: %d action Wakeup pattern 0x%x in fw",
				__func__, i, cmd->action_category_map[i]);
		else
			cmd->action_category_map[i] = 0;
	}

	WMA_LOGD("Spectrum mgmt action id drop bitmap: 0x%x",
			cmd->action_per_category[SIR_MAC_ACTION_SPECTRUM_MGMT]);
	WMA_LOGD("Public action id drop bitmap: 0x%x",
			cmd->action_per_category[SIR_MAC_ACTION_PUBLIC_USAGE]);

	err = wmi_unified_action_frame_patterns_cmd(wma->wmi_handle, cmd);
	if (err) {
		WMA_LOGE("Failed to config wow action frame map, ret %d", err);
		qdf_mem_free(cmd);
		return QDF_STATUS_E_FAILURE;
	}

	qdf_mem_free(cmd);
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_wow_sta() - set WOW patterns in sta mode
 * @wma: wma handle
 * @vdev_id: vdev id
 *
 * Configures default WOW pattern for the given vdev_id which is in sta mode.
 *
 * Return: QDF status
 */
static QDF_STATUS wma_wow_sta(tp_wma_handle wma, uint8_t vdev_id)
{
	uint8_t arp_offset = 12;
	uint8_t mac_mask[IEEE80211_ADDR_LEN];
	QDF_STATUS ret = QDF_STATUS_SUCCESS;

	qdf_mem_set(&mac_mask, IEEE80211_ADDR_LEN, 0xFF);
	/*
	 * Set up unicast wow pattern
	 * WoW pattern ID should be unique for each vdev
	 * Different WoW patterns can use same pattern ID
	 */
	ret = wma_send_wow_patterns_to_fw(wma, vdev_id,
			wma_get_and_increment_wow_default_ptrn(wma, vdev_id),
			wma->interfaces[vdev_id].addr,
			IEEE80211_ADDR_LEN, 0, mac_mask,
			IEEE80211_ADDR_LEN, false);
	if (ret != QDF_STATUS_SUCCESS) {
		WMA_LOGE("Failed to add WOW unicast pattern ret %d", ret);
		return ret;
	}

	ret = wma_configure_ssdp(wma, vdev_id);
	if (ret != QDF_STATUS_SUCCESS)
		WMA_LOGE("Failed to configure SSDP patterns to FW");

	/* when arp offload or ns offloaded is disabled
	 * from ini file, configure broad cast arp pattern
	 * to fw, so that host can wake up
	 */
	if (!(wma->ol_ini_info & 0x1)) {
		/* Setup all ARP pkt pattern */
		WMA_LOGD("ARP offload is disabled in INI enable WoW for ARP");
		ret = wma_send_wow_patterns_to_fw(wma, vdev_id,
			wma_get_and_increment_wow_default_ptrn(wma, vdev_id),
			arp_ptrn, sizeof(arp_ptrn), arp_offset,
			arp_mask, sizeof(arp_mask), false);
		if (ret != QDF_STATUS_SUCCESS) {
			WMA_LOGE("Failed to add WOW ARP pattern");
			return ret;
		}
	}

	/* for NS or NDP offload packets */
	if (!(wma->ol_ini_info & 0x2)) {
		/* Setup all NS pkt pattern */
		WMA_LOGD("NS offload is disabled in INI enable WoW for NS");
		ret = wma_send_wow_patterns_to_fw(wma, vdev_id,
			wma_get_and_increment_wow_default_ptrn(wma, vdev_id),
			ns_ptrn, sizeof(arp_ptrn), arp_offset,
			arp_mask, sizeof(arp_mask), false);
		if (ret != QDF_STATUS_SUCCESS) {
			WMA_LOGE("Failed to add WOW NS pattern");
			return ret;
		}
	}

	return ret;
}

/**
 * wma_register_wow_default_patterns() - register default wow patterns with fw
 * @handle: Pointer to wma handle
 * @vdev_id: vdev id
 *
 * WoW default wake up pattern rule is:
 *  - For STA & P2P CLI mode register for same STA specific wow patterns
 *  - For SAP/P2P GO & IBSS mode register for same SAP specific wow patterns
 *
 * Return: none
 */
void wma_register_wow_default_patterns(WMA_HANDLE handle, uint8_t vdev_id)
{
	tp_wma_handle wma = handle;
	struct wma_txrx_node *iface;

	if (vdev_id >= wma->max_bssid) {
		WMA_LOGE("Invalid vdev id %d", vdev_id);
		return;
	}
	iface = &wma->interfaces[vdev_id];

	if (iface->ptrn_match_enable) {
		if (wma_is_vdev_in_beaconning_mode(wma, vdev_id)) {
			/* Configure SAP/GO/IBSS mode default wow patterns */
			WMA_LOGD("Config SAP specific default wow patterns vdev_id %d",
				 vdev_id);
			wma_wow_ap(wma, vdev_id);
		} else {
			/* Configure STA/P2P CLI mode default wow patterns */
			WMA_LOGD("Config STA specific default wow patterns vdev_id %d",
				vdev_id);
			wma_wow_sta(wma, vdev_id);
			if (wma->IsRArateLimitEnabled) {
				WMA_LOGD("Config STA RA limit wow patterns vdev_id %d",
					vdev_id);
				wma_wow_sta_ra_filter(wma, vdev_id);
			}
		}
	}
}


/**
 * wma_register_wow_wakeup_events() - register vdev specific wake events with fw
 * @handle: Pointer to wma handle
 * @vdev_id: vdev Id
 * @vdev_type: vdev type
 * @vdev_subtype: vdev sub type
 *
 * WoW wake up event rule is following:
 * 1) STA mode and P2P CLI mode wake up events are same
 * 2) SAP mode and P2P GO mode wake up events are same
 * 3) IBSS mode wake events are same as STA mode plus WOW_BEACON_EVENT
 *
 * Return: none
 */
void wma_register_wow_wakeup_events(WMA_HANDLE handle,
				uint8_t vdev_id,
				uint8_t vdev_type,
				uint8_t vdev_subtype)
{
	tp_wma_handle wma = handle;
	uint32_t event_bitmap[WMI_WOW_MAX_EVENT_BM_LEN] = {0};

	WMA_LOGD("vdev_type %d vdev_subtype %d vdev_id %d", vdev_type,
			vdev_subtype, vdev_id);

	if ((WMI_VDEV_TYPE_STA == vdev_type) ||
		((WMI_VDEV_TYPE_AP == vdev_type) &&
		 (WMI_UNIFIED_VDEV_SUBTYPE_P2P_DEVICE == vdev_subtype))) {
		/* Configure STA/P2P CLI mode specific default wake up events */
		wma_set_sta_wow_bitmask(event_bitmap,
					WMI_WOW_MAX_EVENT_BM_LEN);

		if ((wma->interfaces[vdev_id].in_bmps == true ||
		     wma->in_imps == true) &&
		    (wma->auto_power_save_enabled ==
		     CDS_FW_TO_SEND_WOW_IND_ON_PWR_FAILURE))
			wma_set_wow_event_bitmap(
					 WOW_CHIP_POWER_FAILURE_DETECT_EVENT,
					 WMI_WOW_MAX_EVENT_BM_LEN,
					 event_bitmap);

		wma_add_wow_wakeup_event(wma, vdev_id, event_bitmap, true);
	} else if (WMI_VDEV_TYPE_IBSS == vdev_type) {
		/* Configure IBSS mode specific default wake up events */
		wma_set_sta_wow_bitmask(event_bitmap,
					WMI_WOW_MAX_EVENT_BM_LEN);
		wma_set_wow_event_bitmap(WOW_BEACON_EVENT,
					 WMI_WOW_MAX_EVENT_BM_LEN,
					 event_bitmap);
		wma_add_wow_wakeup_event(wma, vdev_id, event_bitmap, true);
	} else if (WMI_VDEV_TYPE_AP == vdev_type) {
		/* Configure SAP/GO mode specific default wake up events */
		wma_set_sap_wow_bitmask(event_bitmap,
					WMI_WOW_MAX_EVENT_BM_LEN);
		wma_add_wow_wakeup_event(wma, vdev_id, event_bitmap, true);
	} else if (WMI_VDEV_TYPE_NDI == vdev_type) {
		/*
		 * Configure NAN data path specific default wake up events.
		 * Following routine sends the command to firmware.
		 */
		wma_ndp_add_wow_wakeup_event(wma, vdev_id);
		return;
	}
	WMA_LOGE("unknown type %d subtype %d", vdev_type, vdev_subtype);
	return;
}

/**
 * wma_enable_disable_wakeup_event() -  Configures wow wakeup events
 * @wma: wma handle
 * @vdev_id: vdev id
 * @bitmap: Event bitmap
 * @enable: enable/disable
 *
 * Return: none
 */
void wma_enable_disable_wakeup_event(WMA_HANDLE handle,
				uint32_t vdev_id,
				uint32_t *bitmap,
				bool enable)
{
	tp_wma_handle wma = handle;
	uint32_t event_bitmap[WMI_WOW_MAX_EVENT_BM_LEN] = {0};

	qdf_mem_copy(event_bitmap, bitmap, sizeof(uint32_t) *
		     WMI_WOW_MAX_EVENT_BM_LEN);

	WMA_LOGD("vdev_id %d wake up event 0x%x%x%x%x enable %d",
		vdev_id, bitmap[0], bitmap[1], bitmap[2], bitmap[3], enable);
	wma_add_wow_wakeup_event(wma, vdev_id, event_bitmap, enable);
}

#ifdef FEATURE_WLAN_D0WOW
void wma_set_d0wow_flag(WMA_HANDLE handle, bool flag)
{
	tp_wma_handle wma = handle;

	atomic_set(&wma->in_d0wow, flag);
}

bool wma_read_d0wow_flag(WMA_HANDLE handle)
{
	tp_wma_handle wma = handle;

	return atomic_read(&wma->in_d0wow);
}

/**
 * wma_enable_d0wow_in_fw() - enable d0 wow in fw
 * @wma: wma handle
 *
 * This is for backward compatible with cld2.0.
 * Return: QDF status
 */
QDF_STATUS wma_enable_d0wow_in_fw(WMA_HANDLE handle)
{
	tp_wma_handle wma = handle;
	int host_credits;
	int wmi_pending_cmds;
	QDF_STATUS status;

	qdf_event_reset(&wma->target_suspend);
	wma->wow_nack = 0;

	host_credits = wmi_get_host_credits(wma->wmi_handle);
	wmi_pending_cmds = wmi_get_pending_cmds(wma->wmi_handle);

	WMA_LOGD("Credits:%d; Pending_Cmds: %d",
		 host_credits, wmi_pending_cmds);

	status = wmi_d0wow_enable_send(wma->wmi_handle,
				WMA_WILDCARD_PDEV_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE("Failed to enable D0-WOW in FW!");
		return status;
	}

	status = qdf_wait_for_event_completion(&wma->target_suspend,
		WMA_TGT_SUSPEND_COMPLETE_TIMEOUT);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE("Failed to receive D0-WoW enable HTC ACK from FW! "
			"Credits: %d, pending_cmds: %d",
			wmi_get_host_credits(wma->wmi_handle),
			wmi_get_pending_cmds(wma->wmi_handle));
		cds_trigger_recovery(CDS_SUSPEND_TIMEOUT);

		return status;
	}

	if (wma->wow_nack) {
		WMA_LOGE("FW not ready for D0WOW.");
		return QDF_STATUS_E_AGAIN;
	}

	host_credits = wmi_get_host_credits(wma->wmi_handle);
	wmi_pending_cmds = wmi_get_pending_cmds(wma->wmi_handle);
	if (host_credits < WMI_WOW_REQUIRED_CREDITS) {
		WMA_LOGE("%s: No Credits after HTC ACK:%d, pending_cmds:%d, cannot resume back",
			 __func__, host_credits, wmi_pending_cmds);
		htc_dump_counter_info(wma->htc_handle);
		cds_trigger_recovery(CDS_SUSPEND_TIMEOUT);
	}

	wma->wow.wow_enable_cmd_sent = true;
	wma_set_d0wow_flag(wma, true);

	WMA_LOGD("D0-WOW is enabled successfully in FW.");

	return QDF_STATUS_SUCCESS;
}
#else
void wma_set_d0wow_flag(WMA_HANDLE handle, bool flag)
{
}
bool wma_read_d0wow_flag(WMA_HANDLE handle)
{
	return false;
}
QDF_STATUS wma_enable_d0wow_in_fw(WMA_HANDLE handle)
{
	WMA_LOGE("%s: ERROR- should never enter this function",
		__func__);
	return QDF_STATUS_E_INVAL;
}
#endif /* FEATURE_WLAN_D0WOW */

/**
 * wma_enable_wow_in_fw() - wnable wow in fw
 * @wma: wma handle
 * @wow_flags: bitmap of WMI WOW flags to pass to FW
 *
 * Return: QDF status
 */
QDF_STATUS wma_enable_wow_in_fw(WMA_HANDLE handle, uint32_t wow_flags)
{
	tp_wma_handle wma = handle;
	int ret;
	struct hif_opaque_softc *scn;
	int host_credits;
	int wmi_pending_cmds;
	struct wow_cmd_params param = {0};

	tpAniSirGlobal pMac = cds_get_context(QDF_MODULE_ID_PE);

	if (NULL == pMac) {
		WMA_LOGE("%s: Unable to get PE context", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	qdf_event_reset(&wma->target_suspend);
	wma->wow_nack = false;

	host_credits = wmi_get_host_credits(wma->wmi_handle);
	wmi_pending_cmds = wmi_get_pending_cmds(wma->wmi_handle);

	WMA_LOGD("Credits:%d; Pending_Cmds: %d",
		 host_credits, wmi_pending_cmds);

	param.enable = true;
	param.can_suspend_link = htc_can_suspend_link(wma->htc_handle);
	param.flags = wow_flags;
	ret = wmi_unified_wow_enable_send(wma->wmi_handle, &param,
				   WMA_WILDCARD_PDEV_ID);
	if (ret) {
		WMA_LOGE("Failed to enable wow in fw");
		goto error;
	}

	wmi_set_target_suspend(wma->wmi_handle, true);

	if (qdf_wait_for_event_completion(&wma->target_suspend,
				  WMA_TGT_SUSPEND_COMPLETE_TIMEOUT)
	    != QDF_STATUS_SUCCESS) {
		WMA_LOGE("Failed to receive WoW Enable Ack from FW");
		WMA_LOGE("Credits:%d; Pending_Cmds: %d",
			 wmi_get_host_credits(wma->wmi_handle),
			 wmi_get_pending_cmds(wma->wmi_handle));
		wmi_set_target_suspend(wma->wmi_handle, false);
		cds_trigger_recovery(CDS_SUSPEND_TIMEOUT);

		return QDF_STATUS_E_FAILURE;
	}

	if (wma->wow_nack) {
		WMA_LOGE("FW not ready to WOW");
		wmi_set_target_suspend(wma->wmi_handle, false);
		return QDF_STATUS_E_AGAIN;
	}

	host_credits = wmi_get_host_credits(wma->wmi_handle);
	wmi_pending_cmds = wmi_get_pending_cmds(wma->wmi_handle);

	if (host_credits < WMI_WOW_REQUIRED_CREDITS) {
		WMA_LOGE("%s: No Credits after HTC ACK:%d, pending_cmds:%d, cannot resume back",
			 __func__, host_credits, wmi_pending_cmds);
		htc_dump_counter_info(wma->htc_handle);
		cds_trigger_recovery(CDS_SUSPEND_TIMEOUT);
	}

	WMA_LOGD("WOW enabled successfully in fw: credits:%d pending_cmds: %d",
						host_credits, wmi_pending_cmds);

	scn = cds_get_context(QDF_MODULE_ID_HIF);

	if (scn == NULL) {
		WMA_LOGE("%s: Failed to get HIF context", __func__);
		wmi_set_target_suspend(wma->wmi_handle, false);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAULT;
	}

	wma->wow.wow_enable_cmd_sent = true;

	wmitlv_free_allocated_event_tlvs(event_id, &pb_event);

	return errno;
}

static void wma_wake_event_log_reason(t_wma_handle *wma,
				      WOW_EVENT_INFO_fixed_param *wake_info)
{
	struct wma_txrx_node *vdev;

	/* "Unspecified" means APPS triggered wake, else firmware triggered */
	if (wake_info->wake_reason != WOW_REASON_UNSPECIFIED) {
		vdev = &wma->interfaces[wake_info->vdev_id];
		WMA_LOGA("WLAN triggered wakeup: %s (%d), vdev: %d (%s)",
			 wma_wow_wake_reason_str(wake_info->wake_reason),
			 wake_info->wake_reason,
			 wake_info->vdev_id,
			 wma_vdev_type_str(vdev->type));
	} else if (!wmi_get_runtime_pm_inprogress(wma->wmi_handle)) {
		WMA_LOGA("Non-WLAN triggered wakeup: %s (%d)",
			 wma_wow_wake_reason_str(wake_info->wake_reason),
			 wake_info->wake_reason);
	}

	qdf_wow_wakeup_host_event(wake_info->wake_reason);
	qdf_wma_wow_wakeup_stats_event(wma);
}

/**
 * wma_wow_wakeup_host_event() - wakeup host event handler
 * @handle: wma handle
 * @event: event data
 * @len: buffer length
 *
 * Handler to catch wow wakeup host event. This event will have
 * reason why the firmware has woken the host.
 *
 * Return: Errno
 */
int wma_wow_wakeup_host_event(void *handle, uint8_t *event, uint32_t len)
{
	int errno;
	t_wma_handle *wma = handle;
	WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *event_param;
	WOW_EVENT_INFO_fixed_param *wake_info;

	event_param = (WMI_WOW_WAKEUP_HOST_EVENTID_param_tlvs *)event;
	if (!event_param) {
		WMA_LOGE("Wake event data is null");
		return -EINVAL;
	}

	wake_info = event_param->fixed_param;

	if (wake_info->vdev_id >= wma->max_bssid) {
		WMA_LOGE("%s: received invalid vdev_id %d",
			 __func__, wake_info->vdev_id);
		return -EINVAL;
	}

	wma_wake_event_log_reason(wma, wake_info);

	pmo_ucfg_psoc_wakeup_host_event_received(wma->psoc);

	wma_print_wow_stats(wma, wake_info);
	/* split based on payload type */
	if (is_piggybacked_event(wake_info->wake_reason))
		errno = wma_wake_event_piggybacked(wma, event_param, len);
	else if (event_param->wow_packet_buffer)
		errno = wma_wake_event_packet(wma, event_param, len);
	else
		errno = wma_wake_event_no_payload(wma, event_param, len);

	wma_inc_wow_stats(wma, wake_info);
	wma_print_wow_stats(wma, wake_info);
	wma_acquire_wow_wakelock(wma, wake_info->wake_reason);

	return errno;
}

#ifdef FEATURE_WLAN_D0WOW
/**
 * wma_d0_wow_disable_ack_event() - wakeup host event handler
 * @handle: wma handle
 * @event: event data
 * @len: buffer length
 *
 * Handler to catch D0-WOW disable ACK event.  This event will have
 * reason why the firmware has woken the host.
 * This is for backward compatible with cld2.0.
 *
 * Return: 0 for success or error
 */
int wma_d0_wow_disable_ack_event(void *handle, uint8_t *event, uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle)handle;
	WMI_D0_WOW_DISABLE_ACK_EVENTID_param_tlvs *param_buf;
	wmi_d0_wow_disable_ack_event_fixed_param *resp_data;

	param_buf = (WMI_D0_WOW_DISABLE_ACK_EVENTID_param_tlvs *)event;
	if (!param_buf) {
		WMA_LOGE("Invalid D0-WOW disable ACK event buffer!");
		return -EINVAL;
	}

	resp_data = param_buf->fixed_param;

	pmo_ucfg_psoc_wakeup_host_event_received(wma->psoc);

	WMA_LOGD("Received D0-WOW disable ACK");

	return 0;
}
#else
int wma_d0_wow_disable_ack_event(void *handle, uint8_t *event, uint32_t len)
{
	return 0;
}
#endif

/**
 * wma_pdev_resume_event_handler() - PDEV resume event handler
 * @handle: wma handle
 * @event: event data
 * @len: buffer length
 *
 * Return: 0 for success or error
 */
int wma_pdev_resume_event_handler(void *handle, uint8_t *event, uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;

	WMA_LOGA("Received PDEV resume event");

	pmo_ucfg_psoc_wakeup_host_event_received(wma->psoc);

	return 0;
}

/**
 * wma_del_ts_req() - send DELTS request to fw
 * @wma: wma handle
 * @msg: delts params
 *
 * Return: none
 */
void wma_del_ts_req(tp_wma_handle wma, tDelTsParams *msg)
{
	if (wmi_unified_del_ts_cmd(wma->wmi_handle,
				 msg->sessionId,
				 TID_TO_WME_AC(msg->userPrio))) {
		WMA_LOGP("%s: Failed to send vdev DELTS command", __func__);
	}

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
	if (msg->setRICparams == true)
		wma_set_ric_req(wma, msg, false);
#endif /* WLAN_FEATURE_ROAM_OFFLOAD */
	qdf_mem_free(msg);
}

/**
 * wma_aggr_qos_req() - send aggr qos request to fw
 * @wma: handle to wma
 * @pAggrQosRspMsg - combined struct for all ADD_TS requests.
 *
 * A function to handle WMA_AGGR_QOS_REQ. This will send out
 * ADD_TS requestes to firmware in loop for all the ACs with
 * active flow.
 *
 * Return: none
 */
void wma_aggr_qos_req(tp_wma_handle wma,
		      tAggrAddTsParams *pAggrQosRspMsg)
{
	wmi_unified_aggr_qos_cmd(wma->wmi_handle,
			   (struct aggr_add_ts_param *)pAggrQosRspMsg);
	/* send response to upper layers from here only. */
	wma_send_msg_high_priority(wma, WMA_AGGR_QOS_RSP, pAggrQosRspMsg, 0);
}

#ifdef FEATURE_WLAN_ESE
/**
 * wma_set_tsm_interval() - Set TSM interval
 * @req: pointer to ADDTS request
 *
 * Return: QDF_STATUS_E_FAILURE or QDF_STATUS_SUCCESS
 */
static QDF_STATUS wma_set_tsm_interval(tAddTsParams *req)
{
	/*
	 * msmt_interval is in unit called TU (1 TU = 1024 us)
	 * max value of msmt_interval cannot make resulting
	 * interval_milliseconds overflow 32 bit
	 *
	 */
	uint32_t interval_milliseconds;
	struct cdp_pdev *pdev = cds_get_context(QDF_MODULE_ID_TXRX);

	if (NULL == pdev) {
		WMA_LOGE("%s: Failed to get pdev", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	interval_milliseconds = (req->tsm_interval * 1024) / 1000;

	cdp_tx_set_compute_interval(cds_get_context(QDF_MODULE_ID_SOC),
			pdev,
			interval_milliseconds);
	return QDF_STATUS_SUCCESS;
}
#else
static inline QDF_STATUS wma_set_tsm_interval(tAddTsParams *req)
{
	return QDF_STATUS_SUCCESS;
}
#endif /* FEATURE_WLAN_ESE */

/**
 * wma_add_ts_req() - send ADDTS request to fw
 * @wma: wma handle
 * @msg: ADDTS params
 *
 * Return: none
 */
void wma_add_ts_req(tp_wma_handle wma, tAddTsParams *msg)
{
	struct add_ts_param cmd = {0};

	msg->status = QDF_STATUS_SUCCESS;
	if (wma_set_tsm_interval(msg) == QDF_STATUS_SUCCESS) {

		cmd.sme_session_id = msg->sme_session_id;
		cmd.tspec.tsinfo.traffic.userPrio =
			TID_TO_WME_AC(msg->tspec.tsinfo.traffic.userPrio);
		cmd.tspec.mediumTime = msg->tspec.mediumTime;
		if (wmi_unified_add_ts_cmd(wma->wmi_handle, &cmd))
			msg->status = QDF_STATUS_E_FAILURE;

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
		if (msg->setRICparams == true)
			wma_set_ric_req(wma, msg, true);
#endif /* WLAN_FEATURE_ROAM_OFFLOAD */

	}
	wma_send_msg_high_priority(wma, WMA_ADD_TS_RSP, msg, 0);
}

#ifdef FEATURE_WLAN_ESE

#define TSM_DELAY_HISTROGRAM_BINS 4
/**
 * wma_process_tsm_stats_req() - process tsm stats request
 * @wma_handler - handle to wma
 * @pTsmStatsMsg - TSM stats struct that needs to be populated and
 *         passed in message.
 *
 * A parallel function to WMA_ProcessTsmStatsReq for pronto. This
 * function fetches stats from data path APIs and post
 * WMA_TSM_STATS_RSP msg back to LIM.
 *
 * Return: False since no pnoscan cannot occur
 * when feature flag is not defined.
 */
QDF_STATUS wma_process_tsm_stats_req(tp_wma_handle wma_handler,
				     void *pTsmStatsMsg)
{
	uint8_t counter;
	uint32_t queue_delay_microsec = 0;
	uint32_t tx_delay_microsec = 0;
	uint16_t packet_count = 0;
	uint16_t packet_loss_count = 0;
	tpAniTrafStrmMetrics pTsmMetric = NULL;
	tpAniGetTsmStatsReq pStats = (tpAniGetTsmStatsReq) pTsmStatsMsg;
	tpAniGetTsmStatsRsp pTsmRspParams = NULL;
	int tid = pStats->tid;
	/*
	 * The number of histrogram bin report by data path api are different
	 * than required by TSM, hence different (6) size array used
	 */
	uint16_t bin_values[QCA_TX_DELAY_HIST_REPORT_BINS] = { 0, };
	struct cdp_pdev *pdev = cds_get_context(QDF_MODULE_ID_TXRX);
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);

	if (NULL == pdev) {
		WMA_LOGE("%s: Failed to get pdev", __func__);
		qdf_mem_free(pTsmStatsMsg);
		return QDF_STATUS_E_INVAL;
	}

	/* get required values from data path APIs */
	cdp_tx_delay(soc,
		pdev,
		&queue_delay_microsec,
		&tx_delay_microsec, tid);
	cdp_tx_delay_hist(soc,
		pdev,
		bin_values, tid);
	cdp_tx_packet_count(soc,
		pdev,
		&packet_count,
		&packet_loss_count, tid);

	pTsmRspParams = qdf_mem_malloc(sizeof(*pTsmRspParams));
	if (NULL == pTsmRspParams) {
		QDF_TRACE(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_ERROR,
			  "%s: QDF MEM Alloc Failure", __func__);
		QDF_ASSERT(0);
		qdf_mem_free(pTsmStatsMsg);
		return QDF_STATUS_E_NOMEM;
	}
	pTsmRspParams->staId = pStats->staId;
	pTsmRspParams->rc = QDF_STATUS_E_FAILURE;
	pTsmRspParams->tsmStatsReq = pStats;
	pTsmMetric = &pTsmRspParams->tsmMetrics;
	/* populate pTsmMetric */
	pTsmMetric->UplinkPktQueueDly = queue_delay_microsec;
	/* store only required number of bin values */
	for (counter = 0; counter < TSM_DELAY_HISTROGRAM_BINS; counter++) {
		pTsmMetric->UplinkPktQueueDlyHist[counter] =
			bin_values[counter];
	}
	pTsmMetric->UplinkPktTxDly = tx_delay_microsec;
	pTsmMetric->UplinkPktLoss = packet_loss_count;
	pTsmMetric->UplinkPktCount = packet_count;

	/*
	 * No need to populate roaming delay and roaming count as they are
	 * being populated just before sending IAPP frame out
	 */
	/* post this message to LIM/PE */
	wma_send_msg(wma_handler, WMA_TSM_STATS_RSP, (void *)pTsmRspParams, 0);
	return QDF_STATUS_SUCCESS;
}

#endif /* FEATURE_WLAN_ESE */

/**
 * wma_process_mcbc_set_filter_req() - process mcbc set filter request
 * @wma_handle: wma handle
 * @mcbc_param: mcbc params
 *
 * Return: QDF status
 */
QDF_STATUS wma_process_mcbc_set_filter_req(tp_wma_handle wma_handle,
					   tSirRcvFltMcAddrList *mcbc_param)
{
	return QDF_STATUS_SUCCESS;
}
#endif

#ifdef WLAN_FEATURE_NAN
/**
 * wma_process_cesium_enable_ind() - enables cesium functionality in target
 * @wma: wma handle
 *
 * Return: QDF status
 */
QDF_STATUS wma_process_cesium_enable_ind(tp_wma_handle wma)
{
	QDF_STATUS ret;
	int32_t vdev_id;

	vdev_id = wma_find_vdev_by_type(wma, WMI_VDEV_TYPE_IBSS);
	if (vdev_id < 0) {
		WMA_LOGE("%s: IBSS vdev does not exist could not enable cesium",
			 __func__);
		return QDF_STATUS_E_FAILURE;
	}

	/* Send enable cesium command to target */
	WMA_LOGE("Enable cesium in target for vdevId %d ", vdev_id);
	ret = wma_vdev_set_param(wma->wmi_handle, vdev_id,
				 WMI_VDEV_PARAM_ENABLE_RMC, 1);
	if (ret) {
		WMA_LOGE("Enable cesium failed for vdevId %d", vdev_id);
		return QDF_STATUS_E_FAILURE;
	}
	return QDF_STATUS_SUCCESS;
}
#endif

/**
 * wma_process_get_peer_info_req() - sends get peer info cmd to target
 * @wma: wma handle
 * @preq: get peer info request
 *
 *  Enable WOW if any one of the condition meets,
 *  1) Is any one of vdev in beaconning mode (in AP mode) ?
 *  2) Is any one of vdev in connected state (in STA mode) ?
 *  3) Is PNO in progress in any one of vdev ?
 *  4) Is Extscan in progress in any one of vdev ?
 *  5) Is P2P listen offload in any one of vdev?
 *  6) Is any vdev in NAN data mode? BSS is already started at the
 *     the time of device creation. It is ready to accept data
 *     requests.
 *  7) If LPASS feature is enabled
 *  8) If NaN feature is enabled
 *  If none of above conditions is true then return false
 *
 * Return: true if wma needs to configure wow false otherwise.
 */
QDF_STATUS wma_process_get_peer_info_req
	(tp_wma_handle wma, tSirIbssGetPeerInfoReqParams *pReq)
{
	int32_t ret;
	uint8_t *p;
	uint16_t len;
	wmi_buf_t buf;
	int32_t vdev_id;
	struct cdp_pdev *pdev;
	void *peer;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	uint8_t peer_mac[IEEE80211_ADDR_LEN];
	uint8_t *peer_mac_raw;
	wmi_peer_info_req_cmd_fixed_param *p_get_peer_info_cmd;
	uint8_t bcast_mac[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff,
						  0xff, 0xff, 0xff };

	if (NULL == soc) {
		WMA_LOGE("%s: SOC context is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	vdev_id = wma_find_vdev_by_type(wma, WMI_VDEV_TYPE_IBSS);
	if (vdev_id < 0) {
		WMA_LOGE("%s: IBSS vdev does not exist could not get peer info",
			 __func__);
		return QDF_STATUS_E_FAILURE;
	}

	pdev = cds_get_context(QDF_MODULE_ID_TXRX);
	if (NULL == pdev) {
		WMA_LOGE("%s: Failed to get pdev context", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	if (0xFF == pReq->staIdx) {
		/*get info for all peers */
		qdf_mem_copy(peer_mac, bcast_mac, IEEE80211_ADDR_LEN);
	} else {
		/*get info for a single peer */
		peer = cdp_peer_find_by_local_id(soc,
				pdev, pReq->staIdx);
		if (!peer) {
			WMA_LOGE("%s: Failed to get peer handle using peer id %d",
				__func__, pReq->staIdx);
			return QDF_STATUS_E_FAILURE;
		}
		peer_mac_raw = cdp_peer_get_peer_mac_addr(soc, peer);
		if (peer_mac_raw == NULL) {
			WMA_LOGE("peer_mac_raw is NULL");
			return QDF_STATUS_E_FAILURE;
		}

		WMA_LOGE("%s: staIdx %d peer mac: 0x%2x:0x%2x:0x%2x:0x%2x:0x%2x:0x%2x",
			__func__, pReq->staIdx, peer_mac_raw[0],
			peer_mac_raw[1], peer_mac_raw[2],
			peer_mac_raw[3], peer_mac_raw[4],
			peer_mac_raw[5]);
		qdf_mem_copy(peer_mac, peer_mac_raw, IEEE80211_ADDR_LEN);
	}

	len = sizeof(wmi_peer_info_req_cmd_fixed_param);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s %d: No WMI resource!", __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}

	p = (uint8_t *) wmi_buf_data(buf);
	qdf_mem_zero(p, len);
	p_get_peer_info_cmd = (wmi_peer_info_req_cmd_fixed_param *) p;

	WMITLV_SET_HDR(&p_get_peer_info_cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_peer_info_req_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN
			       (wmi_peer_info_req_cmd_fixed_param));

	p_get_peer_info_cmd->vdev_id = vdev_id;
	WMI_CHAR_ARRAY_TO_MAC_ADDR(peer_mac,
				   &p_get_peer_info_cmd->peer_mac_address);

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_PEER_INFO_REQ_CMDID);
	if (ret != QDF_STATUS_SUCCESS)
		wmi_buf_free(buf);

	WMA_LOGE("IBSS get peer info cmd sent len: %d, vdev %d command id: %d, status: %d",
		len, vdev_id, WMI_PEER_INFO_REQ_CMDID, ret);

	return QDF_STATUS_SUCCESS;
}
#undef BM_LEN
#undef EV_NLO
#undef EV_PWR

#ifdef FEATURE_WLAN_LPHB
/**
 * wma_process_tx_fail_monitor_ind() - sends tx fail monitor cmd to target
 * @wma: wma handle
 * @pReq: tx fail monitor command params
 *
 * LPHB cache, if any item was enabled, should be
 * applied.
 */
QDF_STATUS wma_process_tx_fail_monitor_ind(tp_wma_handle wma,
					tAniTXFailMonitorInd *pReq)
{
	QDF_STATUS ret;
	int32_t vdev_id;

	vdev_id = wma_find_vdev_by_type(wma, WMI_VDEV_TYPE_IBSS);
	if (vdev_id < 0) {
		WMA_LOGE("%s: IBSS vdev does not exist could not send fast tx fail monitor indication message to target",
			__func__);
		return QDF_STATUS_E_FAILURE;
	}
}
#else
void wma_apply_lphb(tp_wma_handle wma) {}
#endif /* FEATURE_WLAN_LPHB */

	/* Send enable cesium command to target */
	WMA_LOGE("send fast tx fail monitor ind cmd target for vdevId %d val %d",
		vdev_id, pReq->tx_fail_count);

	if (pReq->tx_fail_count == 0)
		wma->hddTxFailCb = NULL;
	else
		wma->hddTxFailCb = pReq->txFailIndCallback;
	ret = wma_vdev_set_param(wma->wmi_handle, vdev_id,
				 WMI_VDEV_PARAM_SET_IBSS_TX_FAIL_CNT_THR,
				 pReq->tx_fail_count);
	if (ret) {
		WMA_LOGE("tx fail monitor failed for vdevId %d", vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_process_rmc_enable_ind() - enables RMC functionality in target
 * @wma: wma handle
 *
 * Return: QDF status
 */
QDF_STATUS wma_process_rmc_enable_ind(tp_wma_handle wma)
{
	int ret;
	uint8_t *p;
	uint16_t len;
	wmi_buf_t buf;
	int32_t vdev_id;
	wmi_rmc_set_mode_cmd_fixed_param *p_rmc_enable_cmd;

	vdev_id = wma_find_vdev_by_type(wma, WMI_VDEV_TYPE_IBSS);
	if (vdev_id < 0) {
		WMA_LOGE("%s: IBSS vdev does not exist could not enable RMC",
			 __func__);
		return QDF_STATUS_E_FAILURE;
	}

	len = sizeof(wmi_rmc_set_mode_cmd_fixed_param);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s %d: No WMI resource!", __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}

	p = (uint8_t *) wmi_buf_data(buf);
	qdf_mem_zero(p, len);
	p_rmc_enable_cmd = (wmi_rmc_set_mode_cmd_fixed_param *) p;

	WMITLV_SET_HDR(&p_rmc_enable_cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_rmc_set_mode_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN
			       (wmi_rmc_set_mode_cmd_fixed_param));

	p_rmc_enable_cmd->vdev_id = vdev_id;
	p_rmc_enable_cmd->enable_rmc = WMI_RMC_MODE_ENABLED;

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_RMC_SET_MODE_CMDID);
	if (ret != QDF_STATUS_SUCCESS)
		wmi_buf_free(buf);

	WMA_LOGE("Enable RMC cmd sent len: %d, vdev %d command id: %d, status: %d",
		 len, vdev_id, WMI_RMC_SET_MODE_CMDID, ret);

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_process_rmc_disable_ind() - disables rmc functionality in target
 * @wma: wma handle
 *
 * Return: QDF status
 */
QDF_STATUS wma_process_rmc_disable_ind(tp_wma_handle wma)
{
	int ret;
	uint8_t *p;
	uint16_t len;
	wmi_buf_t buf;
	int32_t vdev_id;
	wmi_rmc_set_mode_cmd_fixed_param *p_rmc_disable_cmd;

	vdev_id = wma_find_vdev_by_type(wma, WMI_VDEV_TYPE_IBSS);
	if (vdev_id < 0) {
		WMA_LOGE("%s: IBSS vdev does not exist could not disable RMC",
			 __func__);
		return QDF_STATUS_E_FAILURE;
	}

	len = sizeof(wmi_rmc_set_mode_cmd_fixed_param);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s %d: No WMI resource!", __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}

	p = (uint8_t *) wmi_buf_data(buf);
	qdf_mem_zero(p, len);
	p_rmc_disable_cmd = (wmi_rmc_set_mode_cmd_fixed_param *) p;

	WMITLV_SET_HDR(&p_rmc_disable_cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_rmc_set_mode_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN
			       (wmi_rmc_set_mode_cmd_fixed_param));

	p_rmc_disable_cmd->vdev_id = vdev_id;
	p_rmc_disable_cmd->enable_rmc = WMI_RMC_MODE_DISABLED;

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_RMC_SET_MODE_CMDID);
	if (ret != QDF_STATUS_SUCCESS)
		wmi_buf_free(buf);

	WMA_LOGE("Disable RMC cmd sent len: %d, vdev %d command id: %d, status: %d",
		 len, vdev_id, WMI_RMC_SET_MODE_CMDID, ret);

	return QDF_STATUS_SUCCESS;
}

#ifdef FEATURE_WLAN_D0WOW
/**
 * wma_process_rmc_action_period_ind() - sends RMC action period to target
 * @wma: wma handle
 *
 * Return: 0 for success or error code
 */
QDF_STATUS wma_process_rmc_action_period_ind(tp_wma_handle wma)
{
	int ret;
	uint8_t *p;
	uint16_t len;
	uint32_t periodicity_msec;
	wmi_buf_t buf;
	int32_t vdev_id;
	wmi_rmc_set_action_period_cmd_fixed_param *p_rmc_cmd;
	struct sAniSirGlobal *mac = cds_get_context(QDF_MODULE_ID_PE);

	if (NULL == mac) {
		WMA_LOGE("%s: MAC mac does not exist", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	vdev_id = wma_find_vdev_by_type(wma, WMI_VDEV_TYPE_IBSS);
	if (vdev_id < 0) {
		WMA_LOGE("%s: IBSS vdev does not exist could not send RMC action period to target",
			 __func__);
		return QDF_STATUS_E_FAILURE;
	}

	len = sizeof(wmi_rmc_set_action_period_cmd_fixed_param);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGE("%s %d: No WMI resource!", __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}

	p = (uint8_t *) wmi_buf_data(buf);
	qdf_mem_zero(p, len);
	p_rmc_cmd = (wmi_rmc_set_action_period_cmd_fixed_param *) p;

	WMITLV_SET_HDR(&p_rmc_cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_rmc_set_action_period_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN
			       (wmi_rmc_set_action_period_cmd_fixed_param));

	if (wlan_cfg_get_int(mac, WNI_CFG_RMC_ACTION_PERIOD_FREQUENCY,
			     &periodicity_msec) != QDF_STATUS_SUCCESS) {
		WMA_LOGE("Failed to get value for RMC action period using default");
		periodicity_msec = WNI_CFG_RMC_ACTION_PERIOD_FREQUENCY_STADEF;
	}

	p_rmc_cmd->vdev_id = vdev_id;
	p_rmc_cmd->periodicity_msec = periodicity_msec;

	ret = wmi_unified_cmd_send(wma->wmi_handle, buf, len,
				   WMI_RMC_SET_ACTION_PERIOD_CMDID);
	if (ret != QDF_STATUS_SUCCESS)
		wmi_buf_free(buf);

	WMA_LOGE("RMC action period %d cmd sent len: %d, vdev %d command id: %d, status: %d",
		periodicity_msec, len, vdev_id, WMI_RMC_SET_ACTION_PERIOD_CMDID,
		ret);

	return QDF_STATUS_SUCCESS;
}
#else
QDF_STATUS wma_disable_d0wow_in_fw(WMA_HANDLE handle)
{
	/* if not define FEATURE_D0_WOW, should not enter this function */
	return QDF_STATUS_E_INVAL;
}
#endif /* FEATURE_WLAN_D0WOW */

/**
 * wma_process_add_periodic_tx_ptrn_ind - add periodic tx ptrn
 * @handle: wma handle
 * @pAddPeriodicTxPtrnParams: tx ptrn params
 *
 * Retrun: QDF status
 */
QDF_STATUS wma_process_add_periodic_tx_ptrn_ind(WMA_HANDLE handle,
						tSirAddPeriodicTxPtrn *
						pAddPeriodicTxPtrnParams)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	struct periodic_tx_pattern *params_ptr;
	uint8_t vdev_id;
	QDF_STATUS status;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue fw add pattern cmd",
			 __func__);
		return QDF_STATUS_E_INVAL;
	}

	params_ptr = qdf_mem_malloc(sizeof(*params_ptr));

	if (!params_ptr) {
		WMA_LOGE(
			"%s: unable to allocate memory for periodic_tx_pattern",
			 __func__);
		return QDF_STATUS_E_NOMEM;
	}

	if (!wma_find_vdev_by_addr(wma_handle,
				   pAddPeriodicTxPtrnParams->mac_address.bytes,
				   &vdev_id)) {
		WMA_LOGE("%s: Failed to find vdev id for %pM", __func__,
			 pAddPeriodicTxPtrnParams->mac_address.bytes);
		return QDF_STATUS_E_INVAL;
	}

	params_ptr->ucPtrnId = pAddPeriodicTxPtrnParams->ucPtrnId;
	params_ptr->ucPtrnSize = pAddPeriodicTxPtrnParams->ucPtrnSize;
	params_ptr->usPtrnIntervalMs =
				pAddPeriodicTxPtrnParams->usPtrnIntervalMs;
	qdf_mem_copy(&params_ptr->mac_address,
			&pAddPeriodicTxPtrnParams->mac_address,
			sizeof(struct qdf_mac_addr));
	qdf_mem_copy(params_ptr->ucPattern,
			pAddPeriodicTxPtrnParams->ucPattern,
			params_ptr->ucPtrnSize);

	status =  wmi_unified_process_add_periodic_tx_ptrn_cmd(
			wma_handle->wmi_handle,	params_ptr, vdev_id);

	qdf_mem_free(params_ptr);
	return status;
}


/**
 * wma_process_del_periodic_tx_ptrn_ind - del periodic tx ptrn
 * @handle: wma handle
 * @pDelPeriodicTxPtrnParams: tx ptrn params
 *
 * Retrun: QDF status
 */
QDF_STATUS wma_process_del_periodic_tx_ptrn_ind(WMA_HANDLE handle,
						tSirDelPeriodicTxPtrn *
						pDelPeriodicTxPtrnParams)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	uint8_t vdev_id;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue Del Pattern cmd",
			 __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_find_vdev_by_addr(wma_handle,
				   pDelPeriodicTxPtrnParams->mac_address.bytes,
				   &vdev_id)) {
		WMA_LOGE("%s: Failed to find vdev id for %pM", __func__,
			 pDelPeriodicTxPtrnParams->mac_address.bytes);
		return QDF_STATUS_E_INVAL;
	}

	return wmi_unified_process_del_periodic_tx_ptrn_cmd(
				wma_handle->wmi_handle, vdev_id,
				pDelPeriodicTxPtrnParams->ucPtrnId);
}

#ifdef WLAN_FEATURE_STATS_EXT
/**
 * wma_stats_ext_req() - request ext stats from fw
 * @wma_ptr: wma handle
 * @preq: stats ext params
 *
 * Return: QDF status
 */
QDF_STATUS wma_stats_ext_req(void *wma_ptr, tpStatsExtRequest preq)
{
	tp_wma_handle wma = (tp_wma_handle) wma_ptr;
	struct stats_ext_params *params;
	size_t params_len;
	QDF_STATUS status;

	if (!wma) {
		WMA_LOGE("%s: wma handle is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	params_len = sizeof(*params) + preq->request_data_len;
	params = qdf_mem_malloc(params_len);

	if (params == NULL) {
		WMA_LOGE(FL("memory allocation failed"));
		return QDF_STATUS_E_NOMEM;
	}

	params->vdev_id = preq->vdev_id;
	params->request_data_len = preq->request_data_len;
	if (preq->request_data_len > 0)
		qdf_mem_copy(params->request_data, preq->request_data,
			     params->request_data_len);

	status = wmi_unified_stats_ext_req_cmd(wma->wmi_handle, params);
	qdf_mem_free(params);

	return status;
}
#endif /* FEATURE_WLAN_ESE */

#endif /* WLAN_FEATURE_STATS_EXT */

#ifdef WLAN_FEATURE_EXTWOW_SUPPORT
/**
 * wma_send_status_of_ext_wow() - send ext wow status to SME
 * @wma: wma handle
 * @status: status
 *
 * Return: none
 */
static void wma_send_status_of_ext_wow(tp_wma_handle wma, bool status)
{
	tSirReadyToExtWoWInd *ready_to_extwow;
	QDF_STATUS vstatus;
	struct scheduler_msg message = {0};
	uint8_t len;

	WMA_LOGD("Posting ready to suspend indication to umac");

	len = sizeof(tSirReadyToExtWoWInd);
	ready_to_extwow = (tSirReadyToExtWoWInd *) qdf_mem_malloc(len);

	if (NULL == ready_to_extwow) {
		WMA_LOGE("%s: Memory allocation failure", __func__);
		return;
	}

	ready_to_extwow->mesgType = eWNI_SME_READY_TO_EXTWOW_IND;
	ready_to_extwow->mesgLen = len;
	ready_to_extwow->status = status;

	message.type = eWNI_SME_READY_TO_EXTWOW_IND;
	message.bodyptr = (void *)ready_to_extwow;
	message.bodyval = 0;

	vstatus = scheduler_post_message(QDF_MODULE_ID_WMA,
					 QDF_MODULE_ID_SME,
					 QDF_MODULE_ID_SME, &message);
	if (vstatus != QDF_STATUS_SUCCESS) {
		WMA_LOGE("Failed to post ready to suspend");
		qdf_mem_free(ready_to_extwow);
	}
}

/**
 * wma_enable_ext_wow() - enable ext wow in fw
 * @wma: wma handle
 * @params: ext wow params
 *
 * Return:0 for success or error code
 */
QDF_STATUS wma_enable_ext_wow(tp_wma_handle wma, tpSirExtWoWParams params)
{
	struct ext_wow_params wow_params = {0};
	QDF_STATUS status;

	if (!wma) {
		WMA_LOGE("%s: wma handle is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	wow_params.vdev_id = params->vdev_id;
	wow_params.type = (enum wmi_ext_wow_type) params->type;
	wow_params.wakeup_pin_num = params->wakeup_pin_num;

	status = wmi_unified_enable_ext_wow_cmd(wma->wmi_handle,
				&wow_params);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	wma_send_status_of_ext_wow(wma, true);
	return status;

}

/**
 * wma_set_app_type1_params_in_fw() - set app type1 params in fw
 * @wma: wma handle
 * @appType1Params: app type1 params
 *
 * Return: QDF status
 */
int wma_set_app_type1_params_in_fw(tp_wma_handle wma,
				   tpSirAppType1Params appType1Params)
{
	int ret;

	ret = wmi_unified_app_type1_params_in_fw_cmd(wma->wmi_handle,
				   (struct app_type1_params *)appType1Params);
	if (ret) {
		WMA_LOGE("%s: Failed to set APP TYPE1 PARAMS", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}
#endif /* WLAN_FEATURE_GTK_OFFLOAD */

/**
 * wma_set_app_type2_params_in_fw() - set app type2 params in fw
 * @wma: wma handle
 * @appType2Params: app type2 params
 *
 * Return: QDF Status
 */
QDF_STATUS wma_set_app_type2_params_in_fw(tp_wma_handle wma,
					  tpSirAppType2Params appType2Params)
{
	struct app_type2_params params = {0};

	if (!wma) {
		WMA_LOGE("%s: wma handle is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	params.vdev_id = appType2Params->vdev_id;
	params.rc4_key_len = appType2Params->rc4_key_len;
	qdf_mem_copy(params.rc4_key, appType2Params->rc4_key, 16);
	params.ip_id = appType2Params->ip_id;
	params.ip_device_ip = appType2Params->ip_device_ip;
	params.ip_server_ip = appType2Params->ip_server_ip;
	params.tcp_src_port = appType2Params->tcp_src_port;
	params.tcp_dst_port = appType2Params->tcp_dst_port;
	params.tcp_seq = appType2Params->tcp_seq;
	params.tcp_ack_seq = appType2Params->tcp_ack_seq;
	params.keepalive_init = appType2Params->keepalive_init;
	params.keepalive_min = appType2Params->keepalive_min;
	params.keepalive_max = appType2Params->keepalive_max;
	params.keepalive_inc = appType2Params->keepalive_inc;
	params.tcp_tx_timeout_val = appType2Params->tcp_tx_timeout_val;
	params.tcp_rx_timeout_val = appType2Params->tcp_rx_timeout_val;
	qdf_mem_copy(&params.gateway_mac, &appType2Params->gateway_mac,
			sizeof(struct qdf_mac_addr));

	return wmi_unified_set_app_type2_params_in_fw_cmd(wma->wmi_handle,
							&params);
}
#endif /* WLAN_FEATURE_EXTWOW_SUPPORT */

#ifdef FEATURE_WLAN_AUTO_SHUTDOWN
/**
 * wma_auto_shutdown_event_handler() - process auto shutdown timer trigger
 * @handle: wma handle
 * @event: event buffer
 * @len: buffer length
 *
 * Return: QDF status
 */
int wma_auto_shutdown_event_handler(void *handle, uint8_t *event,
				    uint32_t len)
{
	wmi_host_auto_shutdown_event_fixed_param *wmi_auto_sh_evt;
	WMI_HOST_AUTO_SHUTDOWN_EVENTID_param_tlvs *param_buf =
		(WMI_HOST_AUTO_SHUTDOWN_EVENTID_param_tlvs *)
		event;

	if (!param_buf || !param_buf->fixed_param) {
		WMA_LOGE("%s:%d: Invalid Auto shutdown timer evt", __func__,
			 __LINE__);
		return -EINVAL;
	}

	wmi_auto_sh_evt = param_buf->fixed_param;

	if (wmi_auto_sh_evt->shutdown_reason
	    != WMI_HOST_AUTO_SHUTDOWN_REASON_TIMER_EXPIRY) {
		WMA_LOGE("%s:%d: Invalid Auto shutdown timer evt", __func__,
			 __LINE__);
		return -EINVAL;
	}

	WMA_LOGD("%s:%d: Auto Shutdown Evt: %d", __func__, __LINE__,
		 wmi_auto_sh_evt->shutdown_reason);
	return wma_post_auto_shutdown_msg();
}

/**
 * wma_set_auto_shutdown_timer_req() - sets auto shutdown timer in firmware
 * @wma: wma handle
 * @auto_sh_cmd: auto shutdown timer value
 *
 * Return: QDF status
 */
QDF_STATUS wma_set_auto_shutdown_timer_req(tp_wma_handle wma_handle,
						  tSirAutoShutdownCmdParams *
						  auto_sh_cmd)
{
	if (auto_sh_cmd == NULL) {
		WMA_LOGE("%s : Invalid Autoshutdown cfg cmd", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	return wmi_unified_set_auto_shutdown_timer_cmd(wma_handle->wmi_handle,
					auto_sh_cmd->timer_val);
}
#endif /* FEATURE_WLAN_AUTO_SHUTDOWN */

#ifdef WLAN_FEATURE_NAN
/**
 * wma_nan_req() - to send nan request to target
 * @wma: wma_handle
 * @nan_req: request data which will be non-null
 *
 * Check if target initial wake up is received and fail PM suspend gracefully
 *
 * Return: -EAGAIN if initial wake up is received else 0
 */
int wma_is_target_wake_up_received(void)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	int32_t event_count;

	if (NULL == wma) {
		WMA_LOGE("%s: wma is NULL", __func__);
		return -EAGAIN;
	}

	if (wma->wow_initial_wake_up) {
		WMA_LOGE("Target initial wake up received try again");
		return -EAGAIN;
	}

	event_count = qdf_atomic_read(&wma->critical_events_in_flight);
	if (event_count) {
		WMA_LOGE("%d critical event(s) in flight; Try again",
			 event_count);
		return -EAGAIN;
	}

	return 0;
}

/**
 * wma_clear_target_wake_up() - clear initial wake up
 *
 * Clear target initial wake up reason
 *
 * Return: 0 for success and negative error code for failure
 */
int wma_clear_target_wake_up(void)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);

	if (NULL == wma) {
		WMA_LOGE("%s: wma is NULL", __func__);
		return -EFAULT;
	}

	params.vdev_id = pDhcpSrvOffloadInfo->vdev_id;
	params.dhcp_offload_enabled =
				pDhcpSrvOffloadInfo->dhcpSrvOffloadEnabled;
	params.dhcp_client_num = pDhcpSrvOffloadInfo->dhcpClientNum;
	params.dhcp_srv_addr = pDhcpSrvOffloadInfo->dhcpSrvIP;

	status = wmi_unified_process_dhcpserver_offload_cmd(
				wma_handle->wmi_handle, &params);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	return 0;
}

/**
 * wma_resume_target() - resume target
 * @handle: wma handle
 *
 * Return: QDF_STATUS_SUCCESS for success or error code
 */
QDF_STATUS wma_set_led_flashing(tp_wma_handle wma_handle,
				struct flashing_req_params *flashing)
{
	QDF_STATUS status;

	if (NULL == pMac) {
		WMA_LOGE("%s: Unable to get PE context", __func__);
		return QDF_STATUS_E_INVAL;
	}
	status = wmi_unified_set_led_flashing_cmd(wma_handle->wmi_handle,
						  flashing);
	return status;
}

int wma_sar_rsp_evt_handler(ol_scn_t handle, uint8_t *event, uint32_t len)
{
	tp_wma_handle wma_handle;
	wmi_unified_t wmi_handle;
	QDF_STATUS status;

	WMA_LOGD(FL("handle:%pK event:%pK len:%u"), handle, event, len);

	wma_handle = handle;
	if (!wma_handle) {
		WMA_LOGE(FL("NULL wma_handle"));
		return QDF_STATUS_E_INVAL;
	}

	wmi_handle = wma_handle->wmi_handle;
	if (!wmi_handle) {
		WMA_LOGE(FL("NULL wmi_handle"));
		return QDF_STATUS_E_INVAL;
	}

	status = wmi_unified_extract_sar2_result_event(wmi_handle,
						       event, len);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE(FL("Event extract failure: %d"), status);
		return -EINVAL;
	}

	return 0;
}
#endif /* FEATURE_WLAN_TDLS */

#ifdef FEATURE_WLAN_CH_AVOID
/**
 * wma_process_ch_avoid_update_req() - handles channel avoid update request
 * @wma_handle: wma handle
 * @ch_avoid_update_req: channel avoid update params
 *
 * Return: QDF status
 */
QDF_STATUS wma_process_ch_avoid_update_req(tp_wma_handle wma_handle,
					   tSirChAvoidUpdateReq *
					   ch_avoid_update_req)
{
	QDF_STATUS status;

	if (!wma_handle) {
		WMA_LOGE("%s: wma handle is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}
	if (ch_avoid_update_req == NULL) {
		WMA_LOGE("%s : ch_avoid_update_req is NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	WMA_LOGD("%s: WMA --> WMI_CHAN_AVOID_UPDATE", __func__);

	status = wmi_unified_process_ch_avoid_update_cmd(
					wma_handle->wmi_handle);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	WMA_LOGD("%s: WMA --> WMI_CHAN_AVOID_UPDATE sent through WMI",
		 __func__);
	return status;
}
#endif

/**
 * wma_send_regdomain_info_to_fw() - send regdomain info to fw
 * @reg_dmn: reg domain
 * @regdmn2G: 2G reg domain
 * @regdmn5G: 5G reg domain
 * @ctl2G: 2G test limit
 * @ctl5G: 5G test limit
 *
 * Return: none
 */
void wma_send_regdomain_info_to_fw(uint32_t reg_dmn, uint16_t regdmn2G,
				   uint16_t regdmn5G, uint8_t ctl2G,
				   uint8_t ctl5G)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	int32_t cck_mask_val = 0;
	struct pdev_params pdev_param = {0};
	QDF_STATUS ret = QDF_STATUS_SUCCESS;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	WMA_LOGD("reg_dmn: %d regdmn2g: %d regdmn5g :%d ctl2g: %d ctl5g: %d",
		 reg_dmn, regdmn2G, regdmn5G, ctl2G, ctl5G);

	if (NULL == wma) {
		WMA_LOGE("%s: wma context is NULL", __func__);
		return;
	}

	status = wmi_unified_send_regdomain_info_to_fw_cmd(wma->wmi_handle,
			reg_dmn, regdmn2G, regdmn5G, ctl2G, ctl5G);
	if (status == QDF_STATUS_E_NOMEM)
		return;

	if ((((reg_dmn & ~CTRY_FLAG) == CTRY_JAPAN15) ||
	     ((reg_dmn & ~CTRY_FLAG) == CTRY_KOREA_ROC)) &&
	    (true == wma->tx_chain_mask_cck))
		cck_mask_val = 1;

	cck_mask_val |= (wma->self_gen_frm_pwr << 16);
	pdev_param.param_id = WMI_PDEV_PARAM_TX_CHAIN_MASK_CCK;
	pdev_param.param_value = cck_mask_val;
	ret = wmi_unified_pdev_param_send(wma->wmi_handle,
					 &pdev_param,
					 WMA_WILDCARD_PDEV_ID);

	if (QDF_IS_STATUS_ERROR(ret))
		WMA_LOGE("failed to set PDEV tx_chain_mask_cck %d",
			 ret);
}

#ifdef FEATURE_WLAN_TDLS
/**
 * wma_tdls_event_handler() - handle TDLS event
 * @handle: wma handle
 * @event: event buffer
 * @len: buffer length
 *
 * Return: none
 */
int wma_tdls_event_handler(void *handle, uint8_t *event, uint32_t len)
{
	/* TODO update with target rx ops */
	return 0;
}

/**
 * wma_set_tdls_offchan_mode() - set tdls off channel mode
 * @handle: wma handle
 * @chan_switch_params: Pointer to tdls channel switch parameter structure
 *
 * This function sets tdls off channel mode
 *
 * Return: 0 on success; Negative errno otherwise
 */
QDF_STATUS wma_set_tdls_offchan_mode(WMA_HANDLE handle,
			      tdls_chan_switch_params *chan_switch_params)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	struct tdls_channel_switch_params params = {0};
	QDF_STATUS ret = QDF_STATUS_SUCCESS;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE(FL(
			    "WMA is closed, can not issue tdls off channel cmd"
			 ));
		ret = -EINVAL;
		goto end;
	}

	if (wma_is_roam_synch_in_progress(wma_handle,
					  chan_switch_params->vdev_id)) {
		WMA_LOGE("%s: roaming in progress, reject offchan mode cmd!",
			 __func__);
		ret = -EPERM;
		goto end;
	}

	params.vdev_id = chan_switch_params->vdev_id;
	params.tdls_off_ch_bw_offset =
			chan_switch_params->tdls_off_ch_bw_offset;
	params.tdls_off_ch = chan_switch_params->tdls_off_ch;
	params.tdls_sw_mode = chan_switch_params->tdls_sw_mode;
	params.oper_class = chan_switch_params->oper_class;
	params.is_responder = chan_switch_params->is_responder;
	qdf_mem_copy(params.peer_mac_addr, chan_switch_params->peer_mac_addr,
		     IEEE80211_ADDR_LEN);

	ret = wmi_unified_set_tdls_offchan_mode_cmd(wma_handle->wmi_handle,
							&params);

end:
	if (chan_switch_params)
		qdf_mem_free(chan_switch_params);
	return ret;
}

/**
 * wma_update_tdls_peer_state() - update TDLS peer state
 * @handle: wma handle
 * @peerStateParams: TDLS peer state params
 *
 * Return: 0 for success or error code
 */
int wma_update_tdls_peer_state(WMA_HANDLE handle,
			       tTdlsPeerStateParams *peerStateParams)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;
	uint32_t i;
	struct cdp_pdev *pdev;
	uint8_t peer_id;
	void *peer;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	uint8_t *peer_mac_addr;
	int ret = 0;
	uint32_t *ch_mhz = NULL;
	bool restore_last_peer = false;
	QDF_STATUS qdf_status;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue cmd", __func__);
		ret = -EINVAL;
		goto end_tdls_peer_state;
	}

	if (!soc) {
		WMA_LOGE("%s: SOC context is NULL", __func__);
		ret = -EINVAL;
		goto end_tdls_peer_state;
	}

	if (wma_is_roam_synch_in_progress(wma_handle,
					  peerStateParams->vdevId)) {
		WMA_LOGE("%s: roaming in progress, reject peer update cmd!",
			 __func__);
		ret = -EPERM;
		goto end_tdls_peer_state;
	}

	/* peer capability info is valid only when peer state is connected */
	if (WMA_TDLS_PEER_STATE_CONNECTED != peerStateParams->peerState) {
		qdf_mem_zero(&peerStateParams->peerCap,
			     sizeof(tTdlsPeerCapParams));
	}

	if (peerStateParams->peerCap.peerChanLen) {
		ch_mhz = qdf_mem_malloc(sizeof(uint32_t) *
				peerStateParams->peerCap.peerChanLen);
		if (ch_mhz == NULL) {
			WMA_LOGE("%s: memory allocation failed", __func__);
			ret = -ENOMEM;
			goto end_tdls_peer_state;
		}
	}

	for (i = 0; i < peerStateParams->peerCap.peerChanLen; ++i) {
		ch_mhz[i] =
			cds_chan_to_freq(peerStateParams->peerCap.peerChan[i].
					 chanId);
	}

	/* Make sure that peer exists before sending peer state cmd*/
	pdev = cds_get_context(QDF_MODULE_ID_TXRX);
	if (!pdev) {
		WMA_LOGE("%s: Failed to find pdev", __func__);
		ret = -EIO;
		goto end_tdls_peer_state;
	}

	peer = cdp_peer_find_by_addr(soc,
			pdev,
			peerStateParams->peerMacAddr,
			&peer_id);
	if (!peer) {
		WMA_LOGE("%s: Failed to get peer handle using peer mac %pM",
				__func__, peerStateParams->peerMacAddr);
		ret = -EIO;
		goto end_tdls_peer_state;
	}

	if (wmi_unified_update_tdls_peer_state_cmd(wma_handle->wmi_handle,
			 (struct tdls_peer_state_params *)peerStateParams,
			 ch_mhz)) {
		WMA_LOGE("%s: failed to send tdls peer update state command",
			 __func__);
		ret = -EIO;
		goto end_tdls_peer_state;
	}

	/* in case of teardown, remove peer from fw */
	if (WMA_TDLS_PEER_STATE_TEARDOWN == peerStateParams->peerState) {
		peer_mac_addr = cdp_peer_get_peer_mac_addr(soc, peer);
		if (peer_mac_addr == NULL) {
			WMA_LOGE("peer_mac_addr is NULL");
			ret = -EIO;
			goto end_tdls_peer_state;
		}

		restore_last_peer = cdp_peer_is_vdev_restore_last_peer(
						soc, peer);

		WMA_LOGD("%s: calling wma_remove_peer for peer " MAC_ADDRESS_STR
			 " vdevId: %d", __func__,
			 MAC_ADDR_ARRAY(peer_mac_addr),
			 peerStateParams->vdevId);
		qdf_status = wma_remove_peer(wma_handle, peer_mac_addr,
				peerStateParams->vdevId, peer, false);
		if (QDF_IS_STATUS_ERROR(qdf_status)) {
			WMA_LOGE(FL("wma_remove_peer failed"));
			ret = -EINVAL;
			goto end_tdls_peer_state;
		}
		cdp_peer_update_last_real_peer(soc,
				pdev, peer, &peer_id,
				restore_last_peer);
	}

end_tdls_peer_state:
	if (ch_mhz)
		qdf_mem_free(ch_mhz);
	if (peerStateParams)
		qdf_mem_free(peerStateParams);
	return ret;
}
#endif /* FEATURE_WLAN_TDLS */


/*
 * wma_process_set_ie_info() - Function to send IE info to firmware
 * @wma:                Pointer to WMA handle
 * @ie_data:       Pointer for ie data
 *
 * This function sends IE information to firmware
 *
 * Return: QDF_STATUS_SUCCESS for success otherwise failure
 *
 */
QDF_STATUS wma_process_set_ie_info(tp_wma_handle wma,
				   struct vdev_ie_info *ie_info)
{
	struct wma_txrx_node *interface;
	struct vdev_ie_info_param cmd = {0};
	int ret;

	if (!ie_info || !wma) {
		WMA_LOGE(FL("input pointer is NULL"));
		return QDF_STATUS_E_FAILURE;
	}

	/* Validate the input */
	if (ie_info->length  <= 0) {
		WMA_LOGE(FL("Invalid IE length"));
		return QDF_STATUS_E_INVAL;
	}

	if (ie_info->vdev_id >= wma->max_bssid) {
		WMA_LOGE(FL("Invalid vdev_id: %d"), ie_info->vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	interface = &wma->interfaces[ie_info->vdev_id];
	if (!wma_is_vdev_valid(ie_info->vdev_id)) {
		WMA_LOGE(FL("vdev_id: %d is not active"), ie_info->vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	cmd.vdev_id = ie_info->vdev_id;
	cmd.ie_id = ie_info->ie_id;
	cmd.length = ie_info->length;
	cmd.band = ie_info->band;
	cmd.data = ie_info->data;
	cmd.ie_source = WMA_SET_VDEV_IE_SOURCE_HOST;

	WMA_LOGD(FL("vdev id: %d, ie_id: %d, band: %d, len: %d"),
		 ie_info->vdev_id, ie_info->ie_id, ie_info->band,
		 ie_info->length);

	QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_DEBUG,
		ie_info->data, ie_info->length);

	ret = wmi_unified_process_set_ie_info_cmd(wma->wmi_handle,
				   &cmd);
	return ret;
}

#ifdef FEATURE_WLAN_APF
/**
 *  wma_get_apf_caps_event_handler() - Event handler for get apf capability
 *  @handle: WMA global handle
 *  @cmd_param_info: command event data
 *  @len: Length of @cmd_param_info
 *
 *  Return: 0 on Success or Errno on failure
 */
int wma_get_apf_caps_event_handler(void *handle, u_int8_t *cmd_param_info,
				   u_int32_t len)
{
	WMI_BPF_CAPABILIY_INFO_EVENTID_param_tlvs  *param_buf;
	wmi_bpf_capability_info_evt_fixed_param *event;
	struct sir_apf_get_offload *apf_get_offload;
	tpAniSirGlobal pmac = (tpAniSirGlobal)cds_get_context(
				QDF_MODULE_ID_PE);

	if (!pmac) {
		WMA_LOGE("%s: Invalid pmac", __func__);
		return -EINVAL;
	}
	if (!pmac->sme.apf_get_offload_cb) {
		WMA_LOGE("%s: Callback not registered", __func__);
		return -EINVAL;
	}

	param_buf = (WMI_BPF_CAPABILIY_INFO_EVENTID_param_tlvs *)cmd_param_info;
	event = param_buf->fixed_param;
	apf_get_offload = qdf_mem_malloc(sizeof(*apf_get_offload));

	if (!apf_get_offload) {
		WMA_LOGP("%s: Memory allocation failed.", __func__);
		return -ENOMEM;
	}

	apf_get_offload->apf_version = event->bpf_version;
	apf_get_offload->max_apf_filters = event->max_bpf_filters;
	apf_get_offload->max_bytes_for_apf_inst =
			event->max_bytes_for_bpf_inst;
	WMA_LOGD("%s: APF capabilities version: %d max apf filter size: %d",
		 __func__, apf_get_offload->apf_version,
		 apf_get_offload->max_bytes_for_apf_inst);

	WMA_LOGD("%s: sending apf capabilities event to hdd", __func__);
	pmac->sme.apf_get_offload_cb(pmac->sme.apf_get_offload_context,
				     apf_get_offload);
	qdf_mem_free(apf_get_offload);
	return 0;
}

QDF_STATUS wma_get_apf_capabilities(tp_wma_handle wma)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	wmi_bpf_get_capability_cmd_fixed_param *cmd;
	wmi_buf_t wmi_buf;
	uint32_t   len;
	u_int8_t *buf_ptr;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE(FL("WMA is closed, can not issue get APF capab"));
		return QDF_STATUS_E_INVAL;
	}

	if (!wmi_service_enabled(wma->wmi_handle, wmi_service_apf_offload)) {
		WMA_LOGE(FL("APF cababilities feature bit not enabled"));
		return QDF_STATUS_E_FAILURE;
	}

	len = sizeof(*cmd);
	wmi_buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(wmi_buf);
	cmd = (wmi_bpf_get_capability_cmd_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
	WMITLV_TAG_STRUC_wmi_bpf_get_capability_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
		wmi_bpf_get_capability_cmd_fixed_param));

	if (wmi_unified_cmd_send(wma->wmi_handle, wmi_buf, len,
				 WMI_BPF_GET_CAPABILITY_CMDID)) {
		WMA_LOGE(FL("Failed to send APF capability command"));
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}
	return status;
}

QDF_STATUS wma_set_apf_instructions(tp_wma_handle wma,
				    struct sir_apf_set_offload *apf_set_offload)
{
	wmi_bpf_set_vdev_instructions_cmd_fixed_param *cmd;
	wmi_buf_t wmi_buf;
	uint32_t   len = 0, len_aligned = 0;
	u_int8_t *buf_ptr;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue set APF capability",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	if (!wmi_service_enabled(wma->wmi_handle,
		wmi_service_apf_offload)) {
		WMA_LOGE(FL("APF offload feature Disabled"));
		return QDF_STATUS_E_NOSUPPORT;
	}

	if (!apf_set_offload) {
		WMA_LOGE("%s: Invalid APF instruction request", __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (apf_set_offload->session_id >= wma->max_bssid) {
		WMA_LOGE(FL("Invalid vdev_id: %d"),
			 apf_set_offload->session_id);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_is_vdev_up(apf_set_offload->session_id)) {
		WMA_LOGE("vdev %d is not up skipping APF offload",
			 apf_set_offload->session_id);
		return QDF_STATUS_E_INVAL;
	}

	if (apf_set_offload->total_length) {
		len_aligned = roundup(apf_set_offload->current_length,
					sizeof(A_UINT32));
		len = len_aligned + WMI_TLV_HDR_SIZE;
	}

	len += sizeof(*cmd);
	wmi_buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE("%s: wmi_buf_alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(wmi_buf);
	cmd = (wmi_bpf_set_vdev_instructions_cmd_fixed_param *) buf_ptr;

	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_bpf_set_vdev_instructions_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
			wmi_bpf_set_vdev_instructions_cmd_fixed_param));
	cmd->vdev_id = apf_set_offload->session_id;
	cmd->filter_id = apf_set_offload->filter_id;
	cmd->total_length = apf_set_offload->total_length;
	cmd->current_offset = apf_set_offload->current_offset;
	cmd->current_length = apf_set_offload->current_length;

	if (apf_set_offload->total_length) {
		buf_ptr +=
			sizeof(wmi_bpf_set_vdev_instructions_cmd_fixed_param);
		WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE, len_aligned);
		buf_ptr += WMI_TLV_HDR_SIZE;
		qdf_mem_copy(buf_ptr, apf_set_offload->program,
			     apf_set_offload->current_length);
	}

	if (wmi_unified_cmd_send(wma->wmi_handle, wmi_buf, len,
				 WMI_BPF_SET_VDEV_INSTRUCTIONS_CMDID)) {
		WMA_LOGE(FL("Failed to send config apf instructions command"));
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}
	WMA_LOGD(FL("APF offload enabled in fw"));

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_send_apf_enable_cmd(WMA_HANDLE handle, uint8_t vdev_id,
				   bool apf_enable)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	tp_wma_handle wma = (tp_wma_handle) handle;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE(FL("WMA is closed, can not issue get APF capab"));
		return QDF_STATUS_E_INVAL;
	}

	if (!WMI_SERVICE_IS_ENABLED(wma->wmi_service_bitmap,
		WMI_SERVICE_BPF_OFFLOAD)) {
		WMA_LOGE(FL("APF cababilities feature bit not enabled"));
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_send_apf_enable_cmd(wma->wmi_handle, vdev_id,
						 apf_enable);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE("Failed to send apf enable/disable cmd");
		return QDF_STATUS_E_FAILURE;
	}

	if (apf_enable)
		WMA_LOGD("Sent APF Enable on vdevid: %d", vdev_id);
	else
		WMA_LOGD("Sent APF Disable on vdevid: %d", vdev_id);

	return status;
}

QDF_STATUS
wma_send_apf_write_work_memory_cmd(WMA_HANDLE handle,
				   struct wmi_apf_write_memory_params
								*write_params)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	tp_wma_handle wma = (tp_wma_handle) handle;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE(FL("WMA is closed, can not issue write APF mem"));
		return QDF_STATUS_E_INVAL;
	}

	if (!WMI_SERVICE_IS_ENABLED(wma->wmi_service_bitmap,
		WMI_SERVICE_BPF_OFFLOAD)) {
		WMA_LOGE(FL("APF cababilities feature bit not enabled"));
		return QDF_STATUS_E_FAILURE;
	}

	if (wmi_unified_send_apf_write_work_memory_cmd(wma->wmi_handle,
						       write_params)) {
		WMA_LOGE(FL("Failed to send APF write mem command"));
		return QDF_STATUS_E_FAILURE;
	}

	WMA_LOGD("Sent APF wite mem on vdevid: %d", write_params->vdev_id);
	return status;
}

int wma_apf_read_work_memory_event_handler(void *handle, uint8_t *evt_buf,
					   uint32_t len)
{
	tp_wma_handle wma_handle;
	wmi_unified_t wmi_handle;
	struct wmi_apf_read_memory_resp_event_params evt_params = {0};
	QDF_STATUS status;
	tpAniSirGlobal pmac = cds_get_context(QDF_MODULE_ID_PE);

	WMA_LOGD(FL("handle:%pK event:%pK len:%u"), handle, evt_buf, len);

	wma_handle = handle;
	if (!wma_handle) {
		WMA_LOGE(FL("NULL wma_handle"));
		return -EINVAL;
	}

	wmi_handle = wma_handle->wmi_handle;
	if (!wmi_handle) {
		WMA_LOGE(FL("NULL wmi_handle"));
		return -EINVAL;
	}

	if (!pmac) {
		WMA_LOGE(FL("Invalid pmac"));
		return -EINVAL;
	}

	if (!pmac->sme.apf_read_mem_cb) {
		WMA_LOGE(FL("Callback not registered"));
		return -EINVAL;
	}

	status = wmi_extract_apf_read_memory_resp_event(wmi_handle,
						evt_buf, &evt_params);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE(FL("Event extract failure: %d"), status);
		return -EINVAL;
	}

	pmac->sme.apf_read_mem_cb(pmac->hdd_handle, &evt_params);

	return 0;
}

QDF_STATUS wma_send_apf_read_work_memory_cmd(WMA_HANDLE handle,
					     struct wmi_apf_read_memory_params
								  *read_params)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	tp_wma_handle wma = (tp_wma_handle) handle;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE(FL("WMA is closed, can not issue read APF memory"));
		return QDF_STATUS_E_INVAL;
	}

	if (!WMI_SERVICE_IS_ENABLED(wma->wmi_service_bitmap,
		WMI_SERVICE_BPF_OFFLOAD)) {
		WMA_LOGE(FL("APF cababilities feature bit not enabled"));
		return QDF_STATUS_E_FAILURE;
	}

	if (wmi_unified_send_apf_read_work_memory_cmd(wma->wmi_handle,
						      read_params)) {
		WMA_LOGE(FL("Failed to send APF read memory command"));
		return QDF_STATUS_E_FAILURE;
	}

	WMA_LOGD("Sent APF read memory on vdevid: %d", read_params->vdev_id);
	return status;
}
#endif /* FEATURE_WLAN_APF */

/**
 * wma_set_tx_rx_aggregation_size() - sets tx rx aggregation sizes
 * @tx_rx_aggregation_size: aggregation size parameters
 *
 * This function sets tx rx aggregation sizes
 *
 * Return: VOS_STATUS_SUCCESS on success, error number otherwise
 */
QDF_STATUS wma_set_tx_rx_aggregation_size(
	struct sir_set_tx_rx_aggregation_size *tx_rx_aggregation_size)
{
	tp_wma_handle wma_handle;
	wmi_vdev_set_custom_aggr_size_cmd_fixed_param *cmd;
	int32_t len;
	wmi_buf_t buf;
	u_int8_t *buf_ptr;
	int ret;

	wma_handle = cds_get_context(QDF_MODULE_ID_WMA);

	if (!tx_rx_aggregation_size) {
		WMA_LOGE("%s: invalid pointer", __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle) {
		WMA_LOGE("%s: WMA context is invald!", __func__);
		return QDF_STATUS_E_INVAL;
	}

	len = sizeof(*cmd);
	buf = wmi_buf_alloc(wma_handle->wmi_handle, len);

	if (!buf) {
		WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
		return QDF_STATUS_E_NOMEM;
	}

	buf_ptr = (u_int8_t *) wmi_buf_data(buf);
	cmd = (wmi_vdev_set_custom_aggr_size_cmd_fixed_param *) buf_ptr;
	qdf_mem_zero(cmd, sizeof(*cmd));

	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_vdev_set_custom_aggr_size_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
			wmi_vdev_set_custom_aggr_size_cmd_fixed_param));

	cmd->vdev_id = tx_rx_aggregation_size->vdev_id;
	cmd->tx_aggr_size = tx_rx_aggregation_size->tx_aggregation_size;
	cmd->rx_aggr_size = tx_rx_aggregation_size->rx_aggregation_size;
	/* bit 2 (aggr_type): TX Aggregation Type (0=A-MPDU, 1=A-MSDU) */
	if (tx_rx_aggregation_size->aggr_type ==
	    WMI_VDEV_CUSTOM_AGGR_TYPE_AMSDU)
		cmd->enable_bitmap |= 0x04;

	WMA_LOGD("tx aggr: %d rx aggr: %d vdev: %d enable_bitmap %d",
		 cmd->tx_aggr_size, cmd->rx_aggr_size, cmd->vdev_id,
		 cmd->enable_bitmap);

	ret = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
				WMI_VDEV_SET_CUSTOM_AGGR_SIZE_CMDID);
	if (ret) {
		WMA_LOGE("%s: Failed to send aggregation size command",
				__func__);
		wmi_buf_free(buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_set_tx_rx_aggregation_size_per_ac(
	struct sir_set_tx_rx_aggregation_size *tx_rx_aggregation_size)
{
	tp_wma_handle wma_handle;
	wmi_vdev_set_custom_aggr_size_cmd_fixed_param *cmd;
	int32_t len;
	wmi_buf_t buf;
	u_int8_t *buf_ptr;
	int ret;
	int queue_num;
	uint32_t tx_aggr_size[4];

	wma_handle = cds_get_context(QDF_MODULE_ID_WMA);

	if (!tx_rx_aggregation_size) {
		WMA_LOGE("%s: invalid pointer", __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle) {
		WMA_LOGE("%s: WMA context is invald!", __func__);
		return QDF_STATUS_E_INVAL;
	}

	tx_aggr_size[0] = tx_rx_aggregation_size->tx_aggregation_size_be;
	tx_aggr_size[1] = tx_rx_aggregation_size->tx_aggregation_size_bk;
	tx_aggr_size[2] = tx_rx_aggregation_size->tx_aggregation_size_vi;
	tx_aggr_size[3] = tx_rx_aggregation_size->tx_aggregation_size_vo;

	for (queue_num = 0; queue_num < 4; queue_num++) {
		if (tx_aggr_size[queue_num] == 0)
			continue;

		len = sizeof(*cmd);
		buf = wmi_buf_alloc(wma_handle->wmi_handle, len);

		if (!buf) {
			WMA_LOGE("%s: Failed allocate wmi buffer", __func__);
			return QDF_STATUS_E_NOMEM;
		}

		buf_ptr = (u_int8_t *)wmi_buf_data(buf);
		cmd = (wmi_vdev_set_custom_aggr_size_cmd_fixed_param *)buf_ptr;
		qdf_mem_zero(cmd, sizeof(*cmd));

		WMITLV_SET_HDR(&cmd->tlv_header,
			       WMITLV_TAG_STRUC_wmi_vdev_set_custom_aggr_size_cmd_fixed_param,
			       WMITLV_GET_STRUCT_TLVLEN(
					wmi_vdev_set_custom_aggr_size_cmd_fixed_param));

		cmd->vdev_id = tx_rx_aggregation_size->vdev_id;
		cmd->rx_aggr_size =
				  tx_rx_aggregation_size->rx_aggregation_size;

		cmd->tx_aggr_size = tx_aggr_size[queue_num];
		/* bit 5: tx_ac_enable, if set, ac bitmap is valid. */
		cmd->enable_bitmap = 0x20 | queue_num;
		/* bit 2 (aggr_type): TX Aggregation Type (0=A-MPDU, 1=A-MSDU) */
		if (tx_rx_aggregation_size->aggr_type ==
		    WMI_VDEV_CUSTOM_AGGR_TYPE_AMSDU)
			cmd->enable_bitmap |= 0x04;

		WMA_LOGD("queue_num: %d, tx aggr: %d rx aggr: %d vdev: %d, bitmap: %d",
			 queue_num, cmd->tx_aggr_size,
			 cmd->rx_aggr_size, cmd->vdev_id,
			 cmd->enable_bitmap);

		ret = wmi_unified_cmd_send(wma_handle->wmi_handle, buf, len,
					WMI_VDEV_SET_CUSTOM_AGGR_SIZE_CMDID);
		if (ret) {
			WMA_LOGE("%s: Failed to send aggregation size command",
				 __func__);
			wmi_buf_free(buf);
			return QDF_STATUS_E_FAILURE;
		}
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS wma_set_sw_retry_by_qos(
	tp_wma_handle handle, uint8_t vdev_id,
	wmi_vdev_custom_sw_retry_type_t retry_type,
	wmi_traffic_ac ac_type,
	uint32_t sw_retry)
{
	wmi_vdev_set_custom_sw_retry_th_cmd_fixed_param *cmd;
	int32_t len;
	wmi_buf_t buf;
	u_int8_t *buf_ptr;
	int ret;

	len = sizeof(*cmd);
	buf = wmi_buf_alloc(handle->wmi_handle, len);

	if (!buf)
		return QDF_STATUS_E_NOMEM;

	buf_ptr = (u_int8_t *)wmi_buf_data(buf);
	cmd = (wmi_vdev_set_custom_sw_retry_th_cmd_fixed_param *)buf_ptr;

	WMITLV_SET_HDR(&cmd->tlv_header,
		       WMITLV_TAG_STRUC_wmi_vdev_set_custom_sw_retry_th_cmd_fixed_param,
		       WMITLV_GET_STRUCT_TLVLEN(
		       wmi_vdev_set_custom_sw_retry_th_cmd_fixed_param));

	cmd->vdev_id = vdev_id;
	cmd->ac_type = ac_type;
	cmd->sw_retry_type = retry_type;
	cmd->sw_retry_th = sw_retry;

	wma_debug("ac_type: %d re_type: %d threshold: %d vid: %d",
		  cmd->ac_type, cmd->sw_retry_type,
		  cmd->sw_retry_th, cmd->vdev_id);

	ret = wmi_unified_cmd_send(handle->wmi_handle,
				   buf, len,
				   WMI_VDEV_SET_CUSTOM_SW_RETRY_TH_CMDID);

	if (ret) {
		wmi_buf_free(buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_set_sw_retry_threshold_per_ac(
	WMA_HANDLE handle,
	struct sir_set_tx_sw_retry_threshold *tx_sw_retry_threshold)
{
	QDF_STATUS ret;
	tp_wma_handle wma_handle;
	uint8_t vdev_id;
	int retry_type, queue_num;
	uint32_t tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_MAX][WMI_AC_MAX];
	uint32_t sw_retry;

	wma_handle = (tp_wma_handle)handle;

	if (!tx_sw_retry_threshold) {
		wma_err("%s: invalid pointer", __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle) {
		wma_err("%s: WMA context is invalid!", __func__);
		return QDF_STATUS_E_INVAL;
	}

	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_AGGR][WMI_AC_BE] =
		tx_sw_retry_threshold->tx_aggr_sw_retry_threshold_be;
	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_AGGR][WMI_AC_BK] =
		tx_sw_retry_threshold->tx_aggr_sw_retry_threshold_bk;
	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_AGGR][WMI_AC_VI] =
		tx_sw_retry_threshold->tx_aggr_sw_retry_threshold_vi;
	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_AGGR][WMI_AC_VO] =
		tx_sw_retry_threshold->tx_aggr_sw_retry_threshold_vo;

	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_NONAGGR][WMI_AC_BE] =
		tx_sw_retry_threshold->tx_non_aggr_sw_retry_threshold_be;
	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_NONAGGR][WMI_AC_BK] =
		tx_sw_retry_threshold->tx_non_aggr_sw_retry_threshold_bk;
	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_NONAGGR][WMI_AC_VI] =
		tx_sw_retry_threshold->tx_non_aggr_sw_retry_threshold_vi;
	tx_sw_retry[WMI_VDEV_CUSTOM_SW_RETRY_TYPE_NONAGGR][WMI_AC_VO] =
		tx_sw_retry_threshold->tx_non_aggr_sw_retry_threshold_vo;

	retry_type = WMI_VDEV_CUSTOM_SW_RETRY_TYPE_NONAGGR;
	while (retry_type < WMI_VDEV_CUSTOM_SW_RETRY_TYPE_MAX) {
		for (queue_num = 0; queue_num < WMI_AC_MAX; queue_num++) {
			if (tx_sw_retry[retry_type][queue_num] == 0)
				continue;

			vdev_id = tx_sw_retry_threshold->vdev_id;
			sw_retry = tx_sw_retry[retry_type][queue_num];
			ret = wma_set_sw_retry_by_qos(wma_handle,
						      vdev_id,
						      retry_type,
						      queue_num,
						      sw_retry);

			if (QDF_IS_STATUS_ERROR(ret))
				return ret;
		}
		retry_type++;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 *  wma_p2p_lo_start() - P2P listen offload start
 *  @params: p2p listen offload parameters
 *
 *  This function sends WMI command to start P2P listen offload.
 *
 *  Return: QDF_STATUS enumeration
 */
QDF_STATUS wma_p2p_lo_start(struct sir_p2p_lo_start *params)
{
	wmi_buf_t buf;
	wmi_p2p_lo_start_cmd_fixed_param *cmd;
	int32_t len = sizeof(*cmd);
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	uint8_t *buf_ptr;
	int ret;
	int device_types_len_aligned, probe_resp_len_aligned;

	if (NULL == wma) {
		WMA_LOGE("%s: wma context is NULL", __func__);
		return QDF_STATUS_E_INVAL;
	}

	device_types_len_aligned = qdf_roundup(params->dev_types_len,
						sizeof(A_UINT32));
	probe_resp_len_aligned = qdf_roundup(params->probe_resp_len,
						sizeof(A_UINT32));

	len += 2 * WMI_TLV_HDR_SIZE + device_types_len_aligned +
			probe_resp_len_aligned;

	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s: failed to allocate memory for p2p lo start",
			 __func__);
		return QDF_STATUS_E_NOMEM;
	}

	cmd = (wmi_p2p_lo_start_cmd_fixed_param *)wmi_buf_data(buf);
	buf_ptr = (uint8_t *) wmi_buf_data(buf);

	WMITLV_SET_HDR(&cmd->tlv_header,
		 WMITLV_TAG_STRUC_wmi_p2p_lo_start_cmd_fixed_param,
		 WMITLV_GET_STRUCT_TLVLEN(
			wmi_p2p_lo_start_cmd_fixed_param));

	cmd->vdev_id = params->vdev_id;
	cmd->ctl_flags = params->ctl_flags;
	cmd->channel = params->freq;
	cmd->period = params->period;
	cmd->interval = params->interval;
	cmd->count = params->count;
	cmd->device_types_len = params->dev_types_len;
	cmd->prob_resp_len = params->probe_resp_len;

	buf_ptr += sizeof(wmi_p2p_lo_start_cmd_fixed_param);
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE,
				device_types_len_aligned);
	buf_ptr += WMI_TLV_HDR_SIZE;
	qdf_mem_copy(buf_ptr, params->device_types, params->dev_types_len);

	buf_ptr += device_types_len_aligned;
	WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_BYTE, probe_resp_len_aligned);
	buf_ptr += WMI_TLV_HDR_SIZE;
	qdf_mem_copy(buf_ptr, params->probe_resp_tmplt, params->probe_resp_len);

	WMA_LOGI("%s: Sending WMI_P2P_LO_START command, channel=%d, period=%d, interval=%d, count=%d",
			__func__, cmd->channel, cmd->period,
			cmd->interval, cmd->count);

	ret = wmi_unified_cmd_send(wma->wmi_handle,
				   buf, len,
				   WMI_P2P_LISTEN_OFFLOAD_START_CMDID);
	if (ret) {
		WMA_LOGE("Failed to send p2p lo start: %d", ret);
		wmi_buf_free(buf);
	}

	WMA_LOGI("%s: Successfully sent WMI_P2P_LO_START", __func__);
	wma->interfaces[params->vdev_id].p2p_lo_in_progress = true;

	return ret;
}

/**
 *  wma_p2p_lo_stop() - P2P listen offload stop
 *  @vdev_id: vdev identifier
 *
 *  This function sends WMI command to stop P2P listen offload.
 *
 *  Return: QDF_STATUS enumeration
 */
QDF_STATUS wma_p2p_lo_stop(u_int32_t vdev_id)
{
	wmi_buf_t buf;
	wmi_p2p_lo_stop_cmd_fixed_param *cmd;
	int32_t len;
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	int ret;

	if (NULL == wma) {
		WMA_LOGE("%s: wma context is NULL", __func__);
		return QDF_STATUS_E_INVAL;
	}

	len = sizeof(*cmd);
	buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!buf) {
		WMA_LOGP("%s: failed to allocate memory for p2p lo stop",
			 __func__);
		return QDF_STATUS_E_NOMEM;
	}
	cmd = (wmi_p2p_lo_stop_cmd_fixed_param *)wmi_buf_data(buf);

	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_wmi_p2p_lo_stop_cmd_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
			wmi_p2p_lo_stop_cmd_fixed_param));

	cmd->vdev_id = vdev_id;

	WMA_LOGI("%s: Sending WMI_P2P_LO_STOP command", __func__);

	ret = wmi_unified_cmd_send(wma->wmi_handle,
				   buf, len,
				   WMI_P2P_LISTEN_OFFLOAD_STOP_CMDID);
	if (ret) {
		WMA_LOGE("Failed to send p2p lo stop: %d", ret);
		wmi_buf_free(buf);
	}

	WMA_LOGI("%s: Successfully sent WMI_P2P_LO_STOP", __func__);
	wma->interfaces[vdev_id].p2p_lo_in_progress = false;

	return ret;
}

/**
 * wma_p2p_lo_event_handler() - p2p lo event
 * @handle: the WMA handle
 * @event_buf: buffer with the event parameters
 * @len: length of the buffer
 *
 * This function receives P2P listen offload stop event from FW and
 * pass the event information to upper layer.
 *
 * Return: 0 on success
 */
int wma_p2p_lo_event_handler(void *handle, uint8_t *event_buf,
				uint32_t len)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	struct sir_p2p_lo_event *event;
	WMI_P2P_LISTEN_OFFLOAD_STOPPED_EVENTID_param_tlvs *param_tlvs;
	wmi_p2p_lo_stopped_event_fixed_param *fix_param;
	tpAniSirGlobal p_mac = cds_get_context(QDF_MODULE_ID_PE);

	if (!wma) {
		WMA_LOGE("%s: Invalid WMA Context", __func__);
		return -EINVAL;
	}

	if (!p_mac) {
		WMA_LOGE("%s: Invalid p_mac", __func__);
		return -EINVAL;
	}

	if (!p_mac->sme.p2p_lo_event_callback) {
		WMA_LOGE("%s: Callback not registered", __func__);
		return -EINVAL;
	}

	param_tlvs = (WMI_P2P_LISTEN_OFFLOAD_STOPPED_EVENTID_param_tlvs *)
								event_buf;
	fix_param = param_tlvs->fixed_param;
	if (fix_param->vdev_id >= wma->max_bssid) {
		WMA_LOGE("%s: received invalid vdev_id %d",
			 __func__, fix_param->vdev_id);
		return -EINVAL;
	}
	event = qdf_mem_malloc(sizeof(*event));
	if (event == NULL) {
		WMA_LOGE("Event allocation failed");
		return -ENOMEM;
	}
	event->vdev_id = fix_param->vdev_id;
	event->reason_code = fix_param->reason;

	p_mac->sme.p2p_lo_event_callback(p_mac->sme.p2p_lo_event_context,
					 event);

	wma->interfaces[event->vdev_id].p2p_lo_in_progress = false;

	return 0;
}

#ifndef QCA_SUPPORT_CP_STATS
/**
 * wma_get_wakelock_stats() - Populates wake lock stats
 * @stats: non-null wakelock structure to populate
 *
 * This function collects wake lock stats
 *
 * Return: QDF_STATUS_SUCCESS on success, error value otherwise
 */
QDF_STATUS wma_get_wakelock_stats(struct sir_wake_lock_stats *stats)
{
	t_wma_handle *wma;
	struct sir_vdev_wow_stats *vstats;
	int i;

	if (!stats) {
		WMA_LOGE("%s: invalid stats pointer", __func__);
		return QDF_STATUS_E_INVAL;
	}

	wma = cds_get_context(QDF_MODULE_ID_WMA);
	if (!wma) {
		WMA_LOGE("%s: invalid WMA context", __func__);
		return QDF_STATUS_E_INVAL;
	}

	/* ensure counters are zeroed */
	qdf_mem_zero(stats, sizeof(*stats));

	/* populate global level stats */
	stats->wow_unspecified_wake_up_count = wma->wow_unspecified_wake_count;

	/* populate vdev level stats */
	for (i = 0; i < wma->max_bssid; ++i) {
		if (!wma->interfaces[i].handle)
			continue;

		vstats = &wma->interfaces[i].wow_stats;

		stats->wow_ucast_wake_up_count += vstats->ucast;
		stats->wow_bcast_wake_up_count += vstats->bcast;
		stats->wow_ipv4_mcast_wake_up_count += vstats->ipv4_mcast;
		stats->wow_ipv6_mcast_wake_up_count += vstats->ipv6_mcast;
		stats->wow_ipv6_mcast_ra_stats += vstats->ipv6_mcast_ra;
		stats->wow_ipv6_mcast_ns_stats += vstats->ipv6_mcast_ns;
		stats->wow_ipv6_mcast_na_stats += vstats->ipv6_mcast_na;
		stats->wow_icmpv4_count += vstats->icmpv4;
		stats->wow_icmpv6_count += vstats->icmpv6;
		stats->wow_rssi_breach_wake_up_count += vstats->rssi_breach;
		stats->wow_low_rssi_wake_up_count += vstats->low_rssi;
		stats->wow_gscan_wake_up_count += vstats->gscan;
		stats->wow_pno_complete_wake_up_count += vstats->pno_complete;
		stats->wow_pno_match_wake_up_count += vstats->pno_match;
		stats->wow_oem_response_wake_up_count += vstats->oem_response;
	}

	return QDF_STATUS_SUCCESS;
}
#endif

#ifdef WLAN_FEATURE_DISA
/**
 * wma_process_fw_test_cmd() - send unit test command to fw.
 * @handle: wma handle
 * @wma_fwtest: fw test command
 *
 * This function send fw test command to fw.
 *
 * Return: none
 */
void wma_process_fw_test_cmd(WMA_HANDLE handle,
			     struct set_fwtest_params *wma_fwtest)
{
	tp_wma_handle wma_handle = (tp_wma_handle) handle;

	if (!wma_handle || !wma_handle->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue fw test cmd",
			 __func__);
		return;
	}

	if (wmi_unified_fw_test_cmd(wma_handle->wmi_handle,
				    (struct set_fwtest_params *)wma_fwtest)) {
		WMA_LOGE("%s: Failed to issue fw test cmd",
			 __func__);
		return;
	}
}

/**
 * wma_enable_disable_caevent_ind() - Issue WMI command to enable or
 * disable ca event indication
 * @wma: wma handler
 * @val: boolean value true or false
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wma_enable_disable_caevent_ind(tp_wma_handle wma, uint8_t val)
{
	WMI_CHAN_AVOID_RPT_ALLOW_CMD_fixed_param *cmd;
	wmi_buf_t wmi_buf;
	uint8_t *buf_ptr;
	uint32_t len;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE(FL("WMA is closed, can not issue set/clear CA"));
		return QDF_STATUS_E_INVAL;
	}

	len = sizeof(*cmd);
	wmi_buf = wmi_buf_alloc(wma->wmi_handle, len);
	if (!wmi_buf) {
		WMA_LOGE(FL("wmi_buf_alloc failed"));
		return QDF_STATUS_E_NOMEM;
	}
	buf_ptr = (uint8_t *) wmi_buf_data(wmi_buf);
	cmd = (WMI_CHAN_AVOID_RPT_ALLOW_CMD_fixed_param *) buf_ptr;
	WMITLV_SET_HDR(&cmd->tlv_header,
		WMITLV_TAG_STRUC_WMI_CHAN_AVOID_RPT_ALLOW_CMD_fixed_param,
		WMITLV_GET_STRUCT_TLVLEN(
				WMI_CHAN_AVOID_RPT_ALLOW_CMD_fixed_param));
	cmd->rpt_allow = val;
	if (wmi_unified_cmd_send(wma->wmi_handle, wmi_buf, len,
				WMI_CHAN_AVOID_RPT_ALLOW_CMDID)) {
		WMA_LOGE(FL("Failed to send enable/disable CA event command"));
		wmi_buf_free(wmi_buf);
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

static wma_sar_cb sar_callback;
static void *sar_context;

static int wma_sar_event_handler(void *handle, uint8_t *evt_buf, uint32_t len)
{
	tp_wma_handle wma_handle;
	wmi_unified_t wmi_handle;
	struct sar_limit_event *event;
	wma_sar_cb callback;
	QDF_STATUS status;

	WMA_LOGI(FL("handle:%pK event:%pK len:%u"), handle, evt_buf, len);

	wma_handle = handle;
	if (!wma_handle) {
		WMA_LOGE(FL("NULL wma_handle"));
		return QDF_STATUS_E_INVAL;
	}

	wmi_handle = wma_handle->wmi_handle;
	if (!wmi_handle) {
		WMA_LOGE(FL("NULL wmi_handle"));
		return QDF_STATUS_E_INVAL;
	}

	event = qdf_mem_malloc(sizeof(*event));
	if (!event) {
		WMA_LOGE(FL("failed to malloc sar_limit_event"));
		return QDF_STATUS_E_NOMEM;
	}

	status = wmi_unified_extract_sar_limit_event(wmi_handle,
						     evt_buf, event);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE(FL("Event extract failure: %d"), status);
		qdf_mem_free(event);
		return QDF_STATUS_E_INVAL;
	}

	callback = sar_callback;
	sar_callback = NULL;
	if (callback)
		callback(sar_context, event);

	qdf_mem_free(event);

	return 0;
}

QDF_STATUS wma_sar_register_event_handlers(WMA_HANDLE handle)
{
	tp_wma_handle wma_handle = handle;
	wmi_unified_t wmi_handle;

	if (!wma_handle) {
		WMA_LOGE(FL("NULL wma_handle"));
		return QDF_STATUS_E_INVAL;
	}

	wmi_handle = wma_handle->wmi_handle;
	if (!wmi_handle) {
		WMA_LOGE(FL("NULL wmi_handle"));
		return QDF_STATUS_E_INVAL;
	}

	return wmi_unified_register_event_handler(wmi_handle,
						  wmi_sar_get_limits_event_id,
						  wma_sar_event_handler,
						  WMA_RX_WORK_CTX);
}
#endif

QDF_STATUS wma_get_sar_limit(WMA_HANDLE handle,
			     wma_sar_cb callback, void *context)
{
	tp_wma_handle wma_handle = handle;
	wmi_unified_t wmi_handle;
	QDF_STATUS status;

	if (!wma_handle) {
		WMA_LOGE(FL("NULL wma_handle"));
		return QDF_STATUS_E_INVAL;
	}

	wmi_handle = wma_handle->wmi_handle;
	if (!wmi_handle) {
		WMA_LOGE(FL("NULL wmi_handle"));
		return QDF_STATUS_E_INVAL;
	}

	sar_callback = callback;
	sar_context = context;
	status = wmi_unified_get_sar_limit_cmd(wmi_handle);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE(FL("wmi_unified_get_sar_limit_cmd() error: %u"),
			 status);
		sar_callback = NULL;
	}

	return status;
}

QDF_STATUS wma_set_sar_limit(WMA_HANDLE handle,
		struct sar_limit_cmd_params *sar_limit_params)
{
	int ret;
	tp_wma_handle wma = (tp_wma_handle) handle;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue set sar limit msg",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	if (sar_limit_params == NULL) {
		WMA_LOGE("%s: set sar limit ptr NULL",
			__func__);
		return QDF_STATUS_E_INVAL;
	}

	ret = wmi_unified_send_sar_limit_cmd(wma->wmi_handle,
				sar_limit_params);

	return ret;
}

QDF_STATUS wma_send_coex_config_cmd(WMA_HANDLE wma_handle,
				    struct coex_config_params *coex_cfg_params)
{
	tp_wma_handle wma = (tp_wma_handle)wma_handle;

	if (!wma || !wma->wmi_handle) {
		WMA_LOGE("%s: WMA is closed, can not issue coex config command",
			 __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (!coex_cfg_params) {
		WMA_LOGE("%s: coex cfg params ptr NULL", __func__);
		return QDF_STATUS_E_INVAL;
	}

	return wmi_unified_send_coex_config_cmd(wma->wmi_handle,
					       coex_cfg_params);
}
#endif

/**
 * wma_get_arp_stats_handler() - handle arp stats data
 * indicated by FW
 * @handle: wma context
 * @data: event buffer
 * @data len: length of event buffer
 *
 * Return: 0 on success
 */
int wma_get_arp_stats_handler(void *handle, uint8_t *data,
			uint32_t data_len)
{
	WMI_VDEV_GET_ARP_STAT_EVENTID_param_tlvs *param_buf;
	wmi_vdev_get_arp_stats_event_fixed_param *data_event;
	wmi_vdev_get_connectivity_check_stats *connect_stats_event;
	uint8_t *buf_ptr;
	struct rsp_stats rsp = {0};
	tpAniSirGlobal mac = cds_get_context(QDF_MODULE_ID_PE);

	if (!mac) {
		WMA_LOGE("%s: Invalid mac context", __func__);
		return -EINVAL;
	}

	if (!mac->sme.get_arp_stats_cb) {
		WMA_LOGE("%s: Callback not registered", __func__);
		return -EINVAL;
	}

	if (data == NULL) {
		WMA_LOGE("%s: invalid pointer", __func__);
		return -EINVAL;
	}
	param_buf = (WMI_VDEV_GET_ARP_STAT_EVENTID_param_tlvs *)data;
	if (!param_buf) {
		WMA_LOGE("%s: Invalid get arp stats event", __func__);
		return -EINVAL;
	}
	data_event = param_buf->fixed_param;
	if (!data_event) {
		WMA_LOGE("%s: Invalid get arp stats data event", __func__);
		return -EINVAL;
	}
	rsp.arp_req_enqueue = data_event->arp_req_enqueue;
	rsp.vdev_id = data_event->vdev_id;
	rsp.arp_req_tx_success = data_event->arp_req_tx_success;
	rsp.arp_req_tx_failure = data_event->arp_req_tx_failure;
	rsp.arp_rsp_recvd = data_event->arp_rsp_recvd;
	rsp.out_of_order_arp_rsp_drop_cnt =
		data_event->out_of_order_arp_rsp_drop_cnt;
	rsp.dad_detected = data_event->dad_detected;
	rsp.connect_status = data_event->connect_status;
	rsp.ba_session_establishment_status =
		data_event->ba_session_establishment_status;

	buf_ptr = (uint8_t *)data_event;
	buf_ptr = buf_ptr + sizeof(wmi_vdev_get_arp_stats_event_fixed_param) +
		  WMI_TLV_HDR_SIZE;
	connect_stats_event = (wmi_vdev_get_connectivity_check_stats *)buf_ptr;

	if (((connect_stats_event->tlv_header & 0xFFFF0000) >> 16 ==
	      WMITLV_TAG_STRUC_wmi_vdev_get_connectivity_check_stats)) {
		rsp.connect_stats_present = true;
		rsp.tcp_ack_recvd = connect_stats_event->tcp_ack_recvd;
		rsp.icmpv4_rsp_recvd = connect_stats_event->icmpv4_rsp_recvd;
		WMA_LOGD("tcp_ack_recvd %d icmpv4_rsp_recvd %d",
			connect_stats_event->tcp_ack_recvd,
			connect_stats_event->icmpv4_rsp_recvd);
	}

	mac->sme.get_arp_stats_cb(mac->hdd_handle, &rsp,
				  mac->sme.get_arp_stats_context);

	return 0;
}

/**
 * wma_unified_power_debug_stats_event_handler() - WMA handler function to
 * handle Power stats event from firmware
 * @handle: Pointer to wma handle
 * @cmd_param_info: Pointer to Power stats event TLV
 * @len: Length of the cmd_param_info
 *
 * Return: 0 on success, error number otherwise
 */
#ifdef WLAN_POWER_DEBUGFS
int wma_unified_power_debug_stats_event_handler(void *handle,
			uint8_t *cmd_param_info, uint32_t len)
{
	WMI_PDEV_CHIP_POWER_STATS_EVENTID_param_tlvs *param_tlvs;
	struct power_stats_response *power_stats_results;
	wmi_pdev_chip_power_stats_event_fixed_param *param_buf;
	uint32_t power_stats_len, stats_registers_len, *debug_registers;

	tpAniSirGlobal mac = (tpAniSirGlobal)cds_get_context(QDF_MODULE_ID_PE);

	param_tlvs =
		(WMI_PDEV_CHIP_POWER_STATS_EVENTID_param_tlvs *) cmd_param_info;

	param_buf = (wmi_pdev_chip_power_stats_event_fixed_param *)
		param_tlvs->fixed_param;
	if (!mac || !mac->sme.power_stats_resp_callback) {
		WMA_LOGD("%s: NULL mac ptr or HDD callback is null", __func__);
		return -EINVAL;
	}

	if (!param_buf) {
		WMA_LOGD("%s: NULL power stats event fixed param", __func__);
		return -EINVAL;
	}

	if (param_buf->num_debug_register > ((WMI_SVC_MSG_MAX_SIZE -
		sizeof(wmi_pdev_chip_power_stats_event_fixed_param)) /
		sizeof(uint32_t)) ||
	    param_buf->num_debug_register > param_tlvs->num_debug_registers) {
		WMA_LOGE("excess payload: LEN num_debug_register:%u",
				param_buf->num_debug_register);
		return -EINVAL;
	}
	debug_registers = param_tlvs->debug_registers;
	stats_registers_len =
		(sizeof(uint32_t) * param_buf->num_debug_register);
	power_stats_len = stats_registers_len + sizeof(*power_stats_results);
	power_stats_results = qdf_mem_malloc(power_stats_len);
	if (!power_stats_results) {
		WMA_LOGD("%s: could not allocate mem for power stats results",
				__func__);
		return -ENOMEM;
	}
	WMA_LOGD("Cumulative sleep time %d cumulative total on time %d deep sleep enter counter %d last deep sleep enter tstamp ts %d debug registers fmt %d num debug register %d",
			param_buf->cumulative_sleep_time_ms,
			param_buf->cumulative_total_on_time_ms,
			param_buf->deep_sleep_enter_counter,
			param_buf->last_deep_sleep_enter_tstamp_ms,
			param_buf->debug_register_fmt,
			param_buf->num_debug_register);

	power_stats_results->cumulative_sleep_time_ms
		= param_buf->cumulative_sleep_time_ms;
	power_stats_results->cumulative_total_on_time_ms
		= param_buf->cumulative_total_on_time_ms;
	power_stats_results->deep_sleep_enter_counter
		= param_buf->deep_sleep_enter_counter;
	power_stats_results->last_deep_sleep_enter_tstamp_ms
		= param_buf->last_deep_sleep_enter_tstamp_ms;
	power_stats_results->debug_register_fmt
		= param_buf->debug_register_fmt;
	power_stats_results->num_debug_register
		= param_buf->num_debug_register;

	power_stats_results->debug_registers
		= (uint32_t *)(power_stats_results + 1);

	qdf_mem_copy(power_stats_results->debug_registers,
			debug_registers, stats_registers_len);

	mac->sme.power_stats_resp_callback(power_stats_results,
			mac->sme.power_debug_stats_context);
	qdf_mem_free(power_stats_results);
	return 0;
}
#else
int wma_unified_power_debug_stats_event_handler(void *handle,
		uint8_t *cmd_param_info, uint32_t len)
{
	return 0;
}
#endif
#ifdef WLAN_FEATURE_BEACON_RECEPTION_STATS
int wma_unified_beacon_debug_stats_event_handler(void *handle,
						 uint8_t *cmd_param_info,
						 uint32_t len)
{
	WMI_VDEV_BCN_RECEPTION_STATS_EVENTID_param_tlvs *param_tlvs;
	struct bcn_reception_stats_rsp *bcn_reception_stats;
	wmi_vdev_bcn_recv_stats_fixed_param *param_buf;
	 struct sAniSirGlobal *mac = cds_get_context(QDF_MODULE_ID_PE);

	param_tlvs =
	   (WMI_VDEV_BCN_RECEPTION_STATS_EVENTID_param_tlvs *)cmd_param_info;
	if (!param_tlvs) {
		WMA_LOGA("%s: Invalid stats event", __func__);
		return -EINVAL;
	}

	param_buf = (wmi_vdev_bcn_recv_stats_fixed_param *)
		param_tlvs->fixed_param;
	if (!param_buf || !mac || !mac->sme.beacon_stats_resp_callback) {
		WMA_LOGD("%s: NULL mac ptr or HDD callback is null", __func__);
		return -EINVAL;
	}

	if (!param_buf) {
		WMA_LOGD("%s: NULL beacon stats event fixed param", __func__);
		return -EINVAL;
	}

	bcn_reception_stats = qdf_mem_malloc(sizeof(*bcn_reception_stats));
	if (!bcn_reception_stats)
		return -ENOMEM;

	bcn_reception_stats->total_bcn_cnt = param_buf->total_bcn_cnt;
	bcn_reception_stats->total_bmiss_cnt = param_buf->total_bmiss_cnt;
	bcn_reception_stats->vdev_id = param_buf->vdev_id;

	WMA_LOGD("Total beacon count %d total beacon miss count %d vdev_id %d",
		 param_buf->total_bcn_cnt,
		 param_buf->total_bmiss_cnt,
		 param_buf->vdev_id);

	qdf_mem_copy(bcn_reception_stats->bmiss_bitmap,
		     param_buf->bmiss_bitmap,
		     MAX_BCNMISS_BITMAP * sizeof(uint32_t));

	mac->sme.beacon_stats_resp_callback(bcn_reception_stats,
			mac->sme.beacon_stats_context);
	qdf_mem_free(bcn_reception_stats);
	return 0;
}
#else
int wma_unified_beacon_debug_stats_event_handler(void *handle,
						 uint8_t *cmd_param_info,
						  uint32_t len)
{
	return 0;
}
#endif

int wma_chan_info_event_handler(void *handle, uint8_t *event_buf,
				uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle)handle;
	WMI_CHAN_INFO_EVENTID_param_tlvs *param_buf;
	wmi_chan_info_event_fixed_param *event;
	struct scan_chan_info buf;
	tpAniSirGlobal mac = NULL;
	struct lim_channel_status *channel_status;

	WMA_LOGD("%s: Enter", __func__);

	if (wma != NULL && wma->cds_context != NULL)
		mac = (tpAniSirGlobal)cds_get_context(QDF_MODULE_ID_PE);

	if (!mac) {
		WMA_LOGE("%s: Invalid mac context", __func__);
		return -EINVAL;
	}

	WMA_LOGD("%s: monitor:%d", __func__, mac->snr_monitor_enabled);
	if (mac->snr_monitor_enabled && mac->chan_info_cb) {
		param_buf =
			(WMI_CHAN_INFO_EVENTID_param_tlvs *)event_buf;
		if (!param_buf) {
			WMA_LOGA("%s: Invalid chan info event", __func__);
			return -EINVAL;
		}

		event = param_buf->fixed_param;
		if (!event) {
			WMA_LOGA("%s: Invalid fixed param", __func__);
			return -EINVAL;
		}
		buf.tx_frame_count = event->tx_frame_cnt;
		buf.clock_freq = event->mac_clk_mhz;
		buf.cmd_flag = event->cmd_flags;
		buf.freq = event->freq;
		buf.noise_floor = event->noise_floor;
		buf.cycle_count = event->cycle_count;
		buf.rx_clear_count = event->rx_clear_count;
		mac->chan_info_cb(&buf);
	}

	if (mac->sap.acs_with_more_param &&
	    mac->sme.currDeviceMode == QDF_SAP_MODE) {
		param_buf = (WMI_CHAN_INFO_EVENTID_param_tlvs *) event_buf;
		if (!param_buf)  {
			WMA_LOGE("Invalid chan info event buffer");
			return -EINVAL;
		}
		event = param_buf->fixed_param;
		channel_status =
			qdf_mem_malloc(sizeof(*channel_status));
		if (!channel_status) {
			WMA_LOGE(FL("Mem alloc fail"));
			return -ENOMEM;
		}
		WMA_LOGD(FL("freq=%d nf=%d rxcnt=%u cyccnt=%u tx_r=%d tx_t=%d"),
			 event->freq,
			 event->noise_floor,
			 event->rx_clear_count,
			 event->cycle_count,
			 event->chan_tx_pwr_range,
			 event->chan_tx_pwr_tp);

		channel_status->channelfreq = event->freq;
		channel_status->noise_floor = event->noise_floor;
		channel_status->rx_clear_count =
			 event->rx_clear_count;
		channel_status->cycle_count = event->cycle_count;
		channel_status->chan_tx_pwr_range =
			 event->chan_tx_pwr_range;
		channel_status->chan_tx_pwr_throughput =
			 event->chan_tx_pwr_tp;
		channel_status->rx_frame_count =
			 event->rx_frame_count;
		channel_status->bss_rx_cycle_count =
			event->my_bss_rx_cycle_count;
		channel_status->rx_11b_mode_data_duration =
			event->rx_11b_mode_data_duration;
		channel_status->tx_frame_count = event->tx_frame_cnt;
		channel_status->mac_clk_mhz = event->mac_clk_mhz;
		channel_status->channel_id =
			cds_freq_to_chan(event->freq);
		channel_status->cmd_flags =
			event->cmd_flags;

		wma_send_msg(handle, WMA_RX_CHN_STATUS_EVENT,
			     (void *)channel_status, 0);
	}

	return 0;
}

int wma_rx_aggr_failure_event_handler(void *handle, u_int8_t *event_buf,
							u_int32_t len)
{
	WMI_REPORT_RX_AGGR_FAILURE_EVENTID_param_tlvs *param_buf;
	struct sir_sme_rx_aggr_hole_ind *rx_aggr_hole_event;
	wmi_rx_aggr_failure_event_fixed_param *rx_aggr_failure_info;
	wmi_rx_aggr_failure_info *hole_info;
	uint32_t i, alloc_len;
	tpAniSirGlobal mac;

	mac = (tpAniSirGlobal)cds_get_context(QDF_MODULE_ID_PE);
	if (!mac || !mac->sme.stats_ext2_cb) {
		WMA_LOGD("%s: NULL mac ptr or HDD callback is null", __func__);
		return -EINVAL;
	}

	param_buf = (WMI_REPORT_RX_AGGR_FAILURE_EVENTID_param_tlvs *)event_buf;
	if (!param_buf) {
		WMA_LOGE("%s: Invalid stats ext event buf", __func__);
		return -EINVAL;
	}

	rx_aggr_failure_info = param_buf->fixed_param;
	hole_info = param_buf->failure_info;

	if (rx_aggr_failure_info->num_failure_info > ((WMI_SVC_MSG_MAX_SIZE -
	    sizeof(*rx_aggr_hole_event)) /
	    sizeof(rx_aggr_hole_event->hole_info_array[0]))) {
		WMA_LOGE("%s: Excess data from WMI num_failure_info %d",
			 __func__, rx_aggr_failure_info->num_failure_info);
		return -EINVAL;
	}

	alloc_len = sizeof(*rx_aggr_hole_event) +
		(rx_aggr_failure_info->num_failure_info)*
		sizeof(rx_aggr_hole_event->hole_info_array[0]);
	rx_aggr_hole_event = qdf_mem_malloc(alloc_len);
	if (NULL == rx_aggr_hole_event) {
		WMA_LOGE("%s: Memory allocation failure", __func__);
		return -ENOMEM;
	}

	rx_aggr_hole_event->hole_cnt = rx_aggr_failure_info->num_failure_info;
	if (rx_aggr_hole_event->hole_cnt > param_buf->num_failure_info) {
		WMA_LOGE("Invalid no of hole count: %d",
				rx_aggr_hole_event->hole_cnt);
		qdf_mem_free(rx_aggr_hole_event);
		return -EINVAL;
	}
	WMA_LOGD("aggr holes_sum: %d\n",
		rx_aggr_failure_info->num_failure_info);
	for (i = 0; i < rx_aggr_hole_event->hole_cnt; i++) {
		rx_aggr_hole_event->hole_info_array[i] =
			hole_info->end_seq - hole_info->start_seq + 1;
		WMA_LOGD("aggr_index: %d\tstart_seq: %d\tend_seq: %d\t"
			"hole_info: %d mpdu lost",
			i, hole_info->start_seq, hole_info->end_seq,
			rx_aggr_hole_event->hole_info_array[i]);
		hole_info++;
	}

	mac->sme.stats_ext2_cb(mac->hdd_handle, rx_aggr_hole_event);
	qdf_mem_free(rx_aggr_hole_event);

	if (event->num_chains_valid > CHAIN_MAX_NUM) {
		WMA_LOGE(FL("Invalid num of chains"));
		return -EINVAL;
	}

int wma_wlan_bt_activity_evt_handler(void *handle, uint8_t *event, uint32_t len)
{
	wmi_coex_bt_activity_event_fixed_param *fixed_param;
	WMI_WLAN_COEX_BT_ACTIVITY_EVENTID_param_tlvs *param_buf =
		(WMI_WLAN_COEX_BT_ACTIVITY_EVENTID_param_tlvs *)event;
	struct scheduler_msg sme_msg = {0};
	QDF_STATUS qdf_status;

	if (!param_buf) {
		WMA_LOGE(FL("Invalid BT activity event buffer"));
		return -EINVAL;
	}

	fixed_param = param_buf->fixed_param;
	if (!fixed_param) {
		WMA_LOGE(FL("Invalid BT activity event fixed param buffer"));
		return -EINVAL;
	}

	WMA_LOGI(FL("Received BT activity event %u"),
		    fixed_param->coex_profile_evt);

	sme_msg.type = eWNI_SME_BT_ACTIVITY_INFO_IND;
	sme_msg.bodyptr = NULL;
	sme_msg.bodyval = fixed_param->coex_profile_evt;

	qdf_status = scheduler_post_message(QDF_MODULE_ID_WMA,
					    QDF_MODULE_ID_SME,
					    QDF_MODULE_ID_SME, &sme_msg);
	if (QDF_IS_STATUS_ERROR(qdf_status)) {
		WMA_LOGE(FL("Failed to post msg to SME"));
		return -EINVAL;
	}

	return 0;
}

int wma_pdev_div_info_evt_handler(void *handle, u_int8_t *event_buf,
	u_int32_t len)
{
	WMI_PDEV_DIV_RSSI_ANTID_EVENTID_param_tlvs *param_buf;
	wmi_pdev_div_rssi_antid_event_fixed_param *event;
	struct chain_rssi_result chain_rssi_result;
	u_int32_t i;
	u_int8_t macaddr[IEEE80211_ADDR_LEN];

	tpAniSirGlobal pmac = (tpAniSirGlobal)cds_get_context(
					QDF_MODULE_ID_PE);
	if (!pmac) {
		WMA_LOGE(FL("Invalid pmac"));
		return -EINVAL;
	}
	/* save the copy of the config params */
	qdf_mem_copy(&wma->ss_configs, req, sizeof(*req));

	if (!pmac->sme.get_chain_rssi_cb) {
		WMA_LOGE(FL("Invalid get_chain_rssi_cb"));
		return -EINVAL;
	}
	param_buf = (WMI_PDEV_DIV_RSSI_ANTID_EVENTID_param_tlvs *) event_buf;
	if (!param_buf) {
		WMA_LOGE(FL("Invalid rssi antid event buffer"));
		return -EINVAL;
	}

	event = param_buf->fixed_param;
	if (!event) {
		WMA_LOGE(FL("Invalid fixed param"));
		return -EINVAL;
	}

	if (event->num_chains_valid > CHAIN_MAX_NUM) {
		WMA_LOGE(FL("Invalid num of chains"));
		return -EINVAL;
	}

	qdf_mem_zero(&chain_rssi_result, sizeof(chain_rssi_result));

	WMI_MAC_ADDR_TO_CHAR_ARRAY(&event->macaddr, macaddr);
	WMA_LOGD(FL("macaddr: " MAC_ADDRESS_STR), MAC_ADDR_ARRAY(macaddr));

	WMA_LOGD(FL("num_chains_valid: %d"), event->num_chains_valid);
	chain_rssi_result.num_chains_valid = event->num_chains_valid;

	qdf_mem_copy(chain_rssi_result.chain_rssi, event->chain_rssi,
		     sizeof(event->chain_rssi));

	qdf_mem_copy(chain_rssi_result.chain_evm, event->chain_evm,
		     sizeof(event->chain_evm));

	qdf_mem_copy(chain_rssi_result.ant_id, event->ant_id,
		     sizeof(event->ant_id));

	for (i = 0; i < chain_rssi_result.num_chains_valid; i++) {
		WMA_LOGD(FL("chain_rssi: %d, chain_evm: %d,ant_id: %d"),
			 chain_rssi_result.chain_rssi[i],
			 chain_rssi_result.chain_evm[i],
			 chain_rssi_result.ant_id[i]);

		chain_rssi_result.chain_rssi[i] +=
			WMA_TGT_NOISE_FLOOR_DBM;
	}

	pmac->sme.get_chain_rssi_cb(pmac->sme.get_chain_rssi_context,
				&chain_rssi_result);

	return 0;
}

int wma_vdev_obss_detection_info_handler(void *handle, uint8_t *event,
					 uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	struct wmi_obss_detect_info *obss_detection;
	QDF_STATUS status;

	if (!event) {
		WMA_LOGE("Invalid obss_detection_info event buffer");
		return -EINVAL;
	}
	WMA_LOGD("aggr holes_sum: %d\n",
		 rx_aggr_failure_info->num_failure_info);
	for (i = 0; i < rx_aggr_hole_event->hole_cnt; i++) {
		rx_aggr_hole_event->hole_info_array[i] =
			hole_info->end_seq - hole_info->start_seq + 1;
		WMA_LOGD("aggr_index: %d\tstart_seq: %d\tend_seq: %d\t"
			"hole_info: %d mpdu lost",
			i, hole_info->start_seq, hole_info->end_seq,
			rx_aggr_hole_event->hole_info_array[i]);
		hole_info++;
	}

	obss_detection = qdf_mem_malloc(sizeof(*obss_detection));
	if (!obss_detection) {
		WMA_LOGE("%s: Failed to malloc", __func__);
		return -ENOMEM;
	}

	status = wmi_unified_extract_obss_detection_info(wma->wmi_handle,
							 event, obss_detection);

	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE("%s: Failed to extract obss info", __func__);
		qdf_mem_free(obss_detection);
		return -EINVAL;
	}

	if (!wma_is_vdev_valid(obss_detection->vdev_id)) {
		WMA_LOGE("%s: Invalid vdev id %d", __func__,
			 obss_detection->vdev_id);
		qdf_mem_free(obss_detection);
		return -EINVAL;
	}
	if (WMI_SERVICE_EXT_IS_ENABLED(wma_handle->wmi_service_bitmap,
		wma_handle->wmi_service_ext_bitmap,
		WMI_SERVICE_DUAL_BEACON_ON_SINGLE_MAC_MCC_SUPPORT)) {
		WMA_LOGD("Support dual beacon on both different and same channel on single MAC");
		return true;
	} else {
		WMA_LOGD("Not support dual beacon on same channel on single MAC");
		return false;
	}
}

	wma_send_msg(wma, WMA_OBSS_DETECTION_INFO, obss_detection, 0);

	return 0;
}

int wma_vdev_bss_color_collision_info_handler(void *handle,
					      uint8_t *event,
					      uint32_t len)
{
	tp_wma_handle wma = (tp_wma_handle) handle;
	struct wmi_obss_color_collision_info *obss_color_info;
	QDF_STATUS status;

	if (!event) {
		WMA_LOGE("Invalid obss_color_collision event buffer");
		return -EINVAL;
	}

	obss_color_info = qdf_mem_malloc(sizeof(*obss_color_info));
	if (!obss_color_info) {
		WMA_LOGE("%s: Failed to malloc", __func__);
		return -ENOMEM;
	}

	status = wmi_unified_extract_obss_color_collision_info(wma->wmi_handle,
							       event,
							       obss_color_info);

	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE("%s: Failed to extract obss color info", __func__);
		qdf_mem_free(obss_color_info);
		return -EINVAL;
	}

	if (!wma_is_vdev_valid(obss_color_info->vdev_id)) {
		WMA_LOGE("%s: Invalid vdev id %d", __func__,
			 obss_color_info->vdev_id);
		qdf_mem_free(obss_color_info);
		return -EINVAL;
	}

	wma_send_msg(wma, WMA_OBSS_COLOR_COLLISION_INFO, obss_color_info, 0);

	return qdf_status;
}
