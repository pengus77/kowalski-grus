/*
 * Copyright (c) 2012-2019 The Linux Foundation. All rights reserved.
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
 * DOC: wlan_hdd_tdls.c
 *
 * WLAN Host Device Driver implementation for TDLS
 */

#include <wlan_hdd_includes.h>
#include <ani_global.h>
#include <wlan_hdd_hostapd.h>
#include <wlan_hdd_trace.h>
#include <net/cfg80211.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/etherdevice.h>
#include <net/ieee80211_radiotap.h>
#include "wlan_hdd_tdls.h"
#include "wlan_hdd_cfg80211.h"
#include "wlan_hdd_assoc.h"
#include "sme_api.h"
#include "cds_sched.h"
#include "wma_types.h"
#include "wlan_policy_mgr_api.h"
#include <qca_vendor.h>

/**
 * enum qca_wlan_vendor_tdls_trigger_mode_hdd_map: Maps the user space TDLS
 *	trigger mode in the host driver.
 * @WLAN_HDD_VENDOR_TDLS_TRIGGER_MODE_EXPLICIT: TDLS Connection and
 *	disconnection handled by user space.
 * @WLAN_HDD_VENDOR_TDLS_TRIGGER_MODE_IMPLICIT: TDLS connection and
 *	disconnection controlled by host driver based on data traffic.
 * @WLAN_HDD_VENDOR_TDLS_TRIGGER_MODE_EXTERNAL: TDLS connection and
 *	disconnection jointly controlled by user space and host driver.
 */
enum qca_wlan_vendor_tdls_trigger_mode_hdd_map {
	WLAN_HDD_VENDOR_TDLS_TRIGGER_MODE_EXPLICIT =
		QCA_WLAN_VENDOR_TDLS_TRIGGER_MODE_EXPLICIT,
	WLAN_HDD_VENDOR_TDLS_TRIGGER_MODE_IMPLICIT =
		QCA_WLAN_VENDOR_TDLS_TRIGGER_MODE_IMPLICIT,
	WLAN_HDD_VENDOR_TDLS_TRIGGER_MODE_EXTERNAL =
		((QCA_WLAN_VENDOR_TDLS_TRIGGER_MODE_EXPLICIT |
		  QCA_WLAN_VENDOR_TDLS_TRIGGER_MODE_IMPLICIT) << 1),
};

/**
 * wlan_hdd_tdls_get_all_peers() - dump all TDLS peer info into output string
 * @adapter: HDD adapter
 * @buf: output string buffer to hold the peer info
 * @buflen: the size of output string buffer
 *
 * Return: The size (in bytes) of the valid peer info in the output buffer
 */
int wlan_hdd_tdls_get_all_peers(struct hdd_adapter *adapter,
				char *buf, int buflen)
{
	int len;
	struct hdd_context *hdd_ctx;

	hdd_enter();

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	if (0 != (wlan_hdd_validate_context(hdd_ctx))) {
		len = scnprintf(buf, buflen,
				"\nHDD context is not valid\n");
		return len;
	}

	if ((QDF_STA_MODE != adapter->device_mode) &&
	    (QDF_P2P_CLIENT_MODE != adapter->device_mode)) {
		len = scnprintf(buf, buflen,
				"\nNo TDLS support for this adapter\n");
		return len;
	}

	return wlan_cfg80211_tdls_get_all_peers(adapter->vdev,
						buf, buflen);
}

static const struct nla_policy
	wlan_hdd_tdls_config_enable_policy[QCA_WLAN_VENDOR_ATTR_TDLS_ENABLE_MAX +
					   1] = {
	[QCA_WLAN_VENDOR_ATTR_TDLS_ENABLE_MAC_ADDR] = {
		.type = NLA_UNSPEC,
		.len = QDF_MAC_ADDR_SIZE},
	[QCA_WLAN_VENDOR_ATTR_TDLS_ENABLE_CHANNEL] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_ENABLE_GLOBAL_OPERATING_CLASS] = {.type =
								NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_ENABLE_MAX_LATENCY_MS] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_ENABLE_MIN_BANDWIDTH_KBPS] = {.type =
								NLA_U32},
};
static const struct nla_policy
	wlan_hdd_tdls_config_disable_policy[QCA_WLAN_VENDOR_ATTR_TDLS_DISABLE_MAX +
					    1] = {
	[QCA_WLAN_VENDOR_ATTR_TDLS_DISABLE_MAC_ADDR] = {
		.type = NLA_UNSPEC,
		.len = QDF_MAC_ADDR_SIZE},
};
static const struct nla_policy
	wlan_hdd_tdls_config_state_change_policy[QCA_WLAN_VENDOR_ATTR_TDLS_STATE_MAX
						 + 1] = {
	[QCA_WLAN_VENDOR_ATTR_TDLS_STATE_MAC_ADDR] = {
		.type = NLA_UNSPEC,
		.len = QDF_MAC_ADDR_SIZE},
	[QCA_WLAN_VENDOR_ATTR_TDLS_NEW_STATE] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_STATE_REASON] = {.type = NLA_S32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_STATE_CHANNEL] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_STATE_GLOBAL_OPERATING_CLASS] = {.type =
								NLA_U32},
};
static const struct nla_policy
	wlan_hdd_tdls_config_get_status_policy
[QCA_WLAN_VENDOR_ATTR_TDLS_GET_STATUS_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_TDLS_GET_STATUS_MAC_ADDR] = {
		.type = NLA_UNSPEC,
		.len = QDF_MAC_ADDR_SIZE},
	[QCA_WLAN_VENDOR_ATTR_TDLS_GET_STATUS_STATE] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_GET_STATUS_REASON] = {.type = NLA_S32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_GET_STATUS_CHANNEL] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_TDLS_GET_STATUS_GLOBAL_OPERATING_CLASS] = {
							.type = NLA_U32},
};

static const struct nla_policy
	wlan_hdd_tdls_mode_configuration_policy
	[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_MAX + 1] = {
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_TRIGGER_MODE] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_TX_STATS_PERIOD] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_TX_THRESHOLD] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_DISCOVERY_PERIOD] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_MAX_DISCOVERY_ATTEMPT] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_IDLE_TIMEOUT] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_IDLE_PACKET_THRESHOLD] = {
						.type = NLA_U32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_SETUP_RSSI_THRESHOLD] = {
						.type = NLA_S32},
		[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_TEARDOWN_RSSI_THRESHOLD] = {
						.type = NLA_S32},
};

/**
 * __wlan_hdd_cfg80211_exttdls_get_status() - handle get status cfg80211 command
 * @wiphy: wiphy
 * @wdev: wireless dev
 * @data: netlink buffer with the mac address of the peer to get the status for
 * @data_len: length of data in bytes
 */
static int
__wlan_hdd_cfg80211_exttdls_get_status(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data,
					 int data_len)
{
	/* TODO */
	return 0;
}

/**
 * __wlan_hdd_cfg80211_configure_tdls_mode() - configure the tdls mode
 * @wiphy: wiphy
 * @wdev: wireless dev
 * @data: netlink buffer
 * @data_len: length of data in bytes
 *
 * Return 0 for success and error code for failure
 */
static int
__wlan_hdd_cfg80211_configure_tdls_mode(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data,
					 int data_len)
{
	struct net_device *dev = wdev->netdev;
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_MAX + 1];
	int ret;
	uint32_t trigger_mode;

	hdd_enter_dev(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EPERM;
	}

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (0 != ret)
		return -EINVAL;

	if (NULL == adapter)
		return -EINVAL;

	if (wlan_cfg80211_nla_parse(tb, QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_MAX,
				    data, data_len,
				    wlan_hdd_tdls_mode_configuration_policy)) {
		hdd_err("Invalid attribute");
		return -EINVAL;
	}

	if (!tb[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_TRIGGER_MODE]) {
		hdd_err("attr tdls trigger mode failed");
		return -EINVAL;
	}
	trigger_mode = nla_get_u32(tb[QCA_WLAN_VENDOR_ATTR_TDLS_CONFIG_TRIGGER_MODE]);
	hdd_debug("TDLS trigger mode %d", trigger_mode);

	if (hdd_ctx->tdls_umac_comp_active) {
		ret = wlan_cfg80211_tdls_configure_mode(adapter->vdev,
							trigger_mode);
		return ret;
	}

	return -EINVAL;
}

/**
 * wlan_hdd_cfg80211_configure_tdls_mode() - configure tdls mode
 * @wiphy:   pointer to wireless wiphy structure.
 * @wdev:    pointer to wireless_dev structure.
 * @data:    Pointer to the data to be passed via vendor interface
 * @data_len:Length of the data to be passed
 *
 * Return:   Return the Success or Failure code.
 */
int wlan_hdd_cfg80211_configure_tdls_mode(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_configure_tdls_mode(wiphy, wdev, data,
							data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * wlan_hdd_cfg80211_exttdls_get_status() - get ext tdls status
 * @wiphy:   pointer to wireless wiphy structure.
 * @wdev:    pointer to wireless_dev structure.
 * @data:    Pointer to the data to be passed via vendor interface
 * @data_len:Length of the data to be passed
 *
 * Return:   Return the Success or Failure code.
 */
int wlan_hdd_cfg80211_exttdls_get_status(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret = 0;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_exttdls_get_status(wiphy, wdev, data,
							data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_exttdls_enable() - enable an externally controllable
 *                                      TDLS peer and set parameters
 * wiphy: wiphy
 * @wdev: wireless dev pointer
 * @data: netlink buffer with peer MAC address and configuration parameters
 * @data_len: size of data in bytes
 *
 * This function sets channel, operation class, maximum latency and minimal
 * bandwidth parameters on a TDLS peer that's externally controllable.
 *
 * Return: 0 for success; negative errno otherwise
 */
static int
__wlan_hdd_cfg80211_exttdls_enable(struct wiphy *wiphy,
				     struct wireless_dev *wdev,
				     const void *data,
				     int data_len)
{
	/* TODO */
	return 0;
}

/**
 * wlan_hdd_cfg80211_exttdls_enable() - enable ext tdls
 * @wiphy:   pointer to wireless wiphy structure.
 * @wdev:    pointer to wireless_dev structure.
 * @data:    Pointer to the data to be passed via vendor interface
 * @data_len:Length of the data to be passed
 *
 * Return:   Return the Success or Failure code.
 */
int wlan_hdd_cfg80211_exttdls_enable(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret = 0;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_exttdls_enable(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_exttdls_disable() - disable an externally controllable
 *                                       TDLS peer
 * wiphy: wiphy
 * @wdev: wireless dev pointer
 * @data: netlink buffer with peer MAC address
 * @data_len: size of data in bytes
 *
 * This function disables an externally controllable TDLS peer
 *
 * Return: 0 for success; negative errno otherwise
 */
static int __wlan_hdd_cfg80211_exttdls_disable(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data,
				      int data_len)
{
	/* TODO */
	return 0;
}

/**
 * wlan_hdd_cfg80211_exttdls_disable() - disable ext tdls
 * @wiphy:   pointer to wireless wiphy structure.
 * @wdev:    pointer to wireless_dev structure.
 * @data:    Pointer to the data to be passed via vendor interface
 * @data_len:Length of the data to be passed
 *
 * Return:   Return the Success or Failure code.
 */
int wlan_hdd_cfg80211_exttdls_disable(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret = 0;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_exttdls_disable(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

#if TDLS_MGMT_VERSION2
/**
 * __wlan_hdd_cfg80211_tdls_mgmt() - handle management actions on a given peer
 * @wiphy: wiphy
 * @dev: net device
 * @peer: MAC address of the TDLS peer
 * @action_code: action code
 * @dialog_token: dialog token
 * @status_code: status code
 * @peer_capability: peer capability
 * @buf: additional IE to include
 * @len: length of buf in bytes
 *
 * Return: 0 if success; negative errno otherwise
 */
static int __wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
				struct net_device *dev, u8 *peer,
				u8 action_code, u8 dialog_token,
				u16 status_code, u32 peer_capability,
				const u8 *buf, size_t len)
#else
/**
 * __wlan_hdd_cfg80211_tdls_mgmt() - handle management actions on a given peer
 * @wiphy: wiphy
 * @dev: net device
 * @peer: MAC address of the TDLS peer
 * @action_code: action code
 * @dialog_token: dialog token
 * @status_code: status code
 * @buf: additional IE to include
 * @len: length of buf in bytes
 *
 * Return: 0 if success; negative errno otherwise
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0))
static int __wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
				struct net_device *dev, const uint8_t *peer,
				uint8_t action_code, uint8_t dialog_token,
				uint16_t status_code, uint32_t peer_capability,
				bool initiator, const uint8_t *buf,
				size_t len)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
static int __wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
				struct net_device *dev, const uint8_t *peer,
				uint8_t action_code, uint8_t dialog_token,
				uint16_t status_code, uint32_t peer_capability,
				const uint8_t *buf, size_t len)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static int __wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
				struct net_device *dev, uint8_t *peer,
				uint8_t action_code, uint8_t dialog_token,
				uint16_t status_code, uint32_t peer_capability,
				const uint8_t *buf, size_t len)
#else
static int __wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
				struct net_device *dev, uint8_t *peer,
				uint8_t action_code, uint8_t dialog_token,
				uint16_t status_code, const uint8_t *buf,
				size_t len)
#endif
#endif
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
#if !(TDLS_MGMT_VERSION2)
	u32 peer_capability;

	peer_capability = 0;
#endif
#endif

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_session_id(adapter->session_id))
		return -EINVAL;

	qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_HDD,
		   TRACE_CODE_HDD_CFG80211_TDLS_MGMT,
		   adapter->session_id, action_code);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (false == hdd_ctx->config->fEnableTDLSSupport) {
		hdd_debug("TDLS Disabled in INI OR not enabled in FW. "
			"Cannot process TDLS commands");
		return -ENOTSUPP;
	}

	if (hdd_ctx->tdls_umac_comp_active)
		return wlan_cfg80211_tdls_mgmt(hdd_ctx->pdev, dev,
					       peer,
					       action_code, dialog_token,
					       status_code, peer_capability,
					       buf, len);

	return -EINVAL;
}

/**
 * wlan_hdd_cfg80211_tdls_mgmt() - cfg80211 tdls mgmt handler function
 * @wiphy: Pointer to wiphy structure.
 * @dev: Pointer to net_device structure.
 * @peer: peer address
 * @action_code: action code
 * @dialog_token: dialog token
 * @status_code: status code
 * @peer_capability: peer capability
 * @buf: buffer
 * @len: Length of @buf
 *
 * This is the cfg80211 tdls mgmt handler function which invokes
 * the internal function @__wlan_hdd_cfg80211_tdls_mgmt with
 * SSR protection.
 *
 * Return: 0 for success, error number on failure.
 */
#if TDLS_MGMT_VERSION2
int wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
					struct net_device *dev,
					u8 *peer, u8 action_code,
					u8 dialog_token,
					u16 status_code, u32 peer_capability,
					const u8 *buf, size_t len)
#else /* TDLS_MGMT_VERSION2 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) || defined(WITH_BACKPORTS)
int wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
					struct net_device *dev,
					const u8 *peer, u8 action_code,
					u8 dialog_token, u16 status_code,
					u32 peer_capability, bool initiator,
					const u8 *buf, size_t len)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
int wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
					struct net_device *dev,
					const u8 *peer, u8 action_code,
					u8 dialog_token, u16 status_code,
					u32 peer_capability, const u8 *buf,
					size_t len)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
int wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
					struct net_device *dev,
					u8 *peer, u8 action_code,
					u8 dialog_token,
					u16 status_code, u32 peer_capability,
					const u8 *buf, size_t len)
#else
int wlan_hdd_cfg80211_tdls_mgmt(struct wiphy *wiphy,
					struct net_device *dev,
					u8 *peer, u8 action_code,
					u8 dialog_token,
					u16 status_code, const u8 *buf,
					size_t len)
#endif
#endif
{
	int ret;

	cds_ssr_protect(__func__);
#if TDLS_MGMT_VERSION2
	ret = __wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer, action_code,
						dialog_token, status_code,
						peer_capability, buf, len);
#else /* TDLS_MGMT_VERSION2 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) || defined(WITH_BACKPORTS)
	ret = __wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer, action_code,
					dialog_token, status_code,
					peer_capability, initiator,
					buf, len);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
	ret = __wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer, action_code,
					dialog_token, status_code,
					peer_capability, buf, len);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	ret = __wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer, action_code,
					dialog_token, status_code,
					peer_capability, buf, len);
#else
	ret = __wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer, action_code,
					dialog_token, status_code, buf, len);
#endif
#endif

	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * wlan_hdd_tdls_extctrl_config_peer() - configure an externally controllable
 *                                       TDLS peer
 * @adapter: HDD adapter
 * @peer: MAC address of the TDLS peer
 * @callback: Callback to set on the peer
 * @chan: Channel
 * @max_latency: Maximum latency
 * @op_class: Operation class
 * @min_bandwidth: Minimal bandwidth
 *
 * Return: 0 on success; negative otherwise
 */
int wlan_hdd_tdls_extctrl_config_peer(struct hdd_adapter *adapter,
				      const uint8_t *peer,
				      cfg80211_exttdls_callback callback,
				      u32 chan,
				      u32 max_latency,
				      u32 op_class, u32 min_bandwidth)
{
	/* TODO */
	return 0;
}

/**
 * wlan_hdd_tdls_extctrl_deconfig_peer() - de-configure an externally
 *                                         controllable TDLS peer
 * @adapter: HDD adapter
 * @peer: MAC address of the tdls peer
 *
 * Return: 0 if success; negative errno otherwisw
 */
int wlan_hdd_tdls_extctrl_deconfig_peer(struct hdd_adapter *adapter,
					const uint8_t *peer)
{
	/* TODO */
	return 0;
}

/**
 * __wlan_hdd_cfg80211_tdls_oper() - helper function to handle cfg80211 operation
 *                                   on an TDLS peer
 * @wiphy: wiphy
 * @dev: net device
 * @peer: MAC address of the TDLS peer
 * @oper: cfg80211 TDLS operation
 *
 * Return: 0 on success; negative errno otherwise
 */
static int __wlan_hdd_cfg80211_tdls_oper(struct wiphy *wiphy,
					 struct net_device *dev,
					 const uint8_t *peer,
					 enum nl80211_tdls_operation oper)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	int status;

	hdd_enter();

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_session_id(adapter->session_id))
		return -EINVAL;

	if (false == hdd_ctx->config->fEnableTDLSSupport) {
		hdd_debug("TDLS Disabled in INI OR not enabled in FW. "
			"Cannot process TDLS commands");
		return -ENOTSUPP;
	}

	qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_HDD,
		   TRACE_CODE_HDD_CFG80211_TDLS_OPER,
		   adapter->session_id, oper);

	if (NULL == peer) {
		hdd_err("Invalid arguments");
		return -EINVAL;
	}

	status = wlan_hdd_validate_context(hdd_ctx);

	if (0 != status)
		return status;

	if (hdd_ctx->tdls_umac_comp_active) {
		status = wlan_cfg80211_tdls_oper(hdd_ctx->pdev,
						 dev, peer, oper);
		hdd_exit();
		return status;
	}

	hdd_exit();
	return -EINVAL;
}

/**
 * wlan_hdd_cfg80211_tdls_oper() - handle cfg80211 operation on an TDLS peer
 * @wiphy: wiphy
 * @dev: net device
 * @peer: MAC address of the TDLS peer
 * @oper: cfg80211 TDLS operation
 *
 * Return: 0 on success; negative errno otherwise
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
int wlan_hdd_cfg80211_tdls_oper(struct wiphy *wiphy,
				struct net_device *dev,
				const uint8_t *peer,
				enum nl80211_tdls_operation oper)
#else
int wlan_hdd_cfg80211_tdls_oper(struct wiphy *wiphy,
				struct net_device *dev,
				uint8_t *peer,
				enum nl80211_tdls_operation oper)
#endif
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_tdls_oper(wiphy, dev, peer, oper);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * wlan_hdd_cfg80211_send_tdls_discover_req() - send out TDLS discovery for
 *                                              a TDLS peer
 * @wiphy: wiphy
 * @dev: net device
 * @peer: MAC address of the peer
 *
 * Return: 0 if success; negative errno otherwise
 */
int wlan_hdd_cfg80211_send_tdls_discover_req(struct wiphy *wiphy,
					     struct net_device *dev, u8 *peer)
{
	hdd_debug("tdls send discover req: " MAC_ADDRESS_STR,
		   MAC_ADDR_ARRAY(peer));
#if TDLS_MGMT_VERSION2
	return wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer,
					   WLAN_TDLS_DISCOVERY_REQUEST, 1, 0, 0,
					   NULL, 0);
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0))
	return wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer,
					   WLAN_TDLS_DISCOVERY_REQUEST, 1, 0,
					   0, 0, NULL, 0);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
	return wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer,
					   WLAN_TDLS_DISCOVERY_REQUEST, 1, 0,
					   0, NULL, 0);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	return wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer,
					   WLAN_TDLS_DISCOVERY_REQUEST, 1, 0,
					   0, NULL, 0);
#else
	return wlan_hdd_cfg80211_tdls_mgmt(wiphy, dev, peer,
					   WLAN_TDLS_DISCOVERY_REQUEST, 1, 0,
					   NULL, 0);
#endif
#endif
}


int hdd_set_tdls_offchannel(struct hdd_context *hdd_ctx,
			    struct hdd_adapter *adapter,
			    int offchannel)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	if (hdd_ctx->tdls_umac_comp_active)
		status = ucfg_set_tdls_offchannel(adapter->vdev,
						  offchannel);
	return qdf_status_to_os_return(status);
}

int hdd_set_tdls_secoffchanneloffset(struct hdd_context *hdd_ctx,
				     struct hdd_adapter *adapter,
				     int offchanoffset)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	if (hdd_ctx->tdls_umac_comp_active)
		status = ucfg_set_tdls_secoffchanneloffset(adapter->vdev,
							   offchanoffset);
	return qdf_status_to_os_return(status);
}

int hdd_set_tdls_offchannelmode(struct hdd_context *hdd_ctx,
				struct hdd_adapter *adapter,
				int offchanmode)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	if (hdd_ctx->tdls_umac_comp_active)
		status = ucfg_set_tdls_offchan_mode(adapter->vdev,
						    offchanmode);
	return qdf_status_to_os_return(status);
}

/**
 * hdd_set_tdls_scan_type - set scan during active tdls session
 * @hdd_ctx: ptr to hdd context.
 * @val: scan type value: 0 or 1.
 *
 * Set scan type during tdls session. If set to 1, that means driver
 * shall maintain tdls link and allow scan regardless if tdls peer is
 * buffer sta capable or not and/or if device is sleep sta capable or
 * not. If tdls peer is not buffer sta capable then during scan there
 * will be loss of Rx packets and Tx would stop when device moves away
 * from tdls channel. If set to 0, then driver shall teardown tdls link
 * before initiating scan if peer is not buffer sta capable and device
 * is not sleep sta capable. By default, scan type is set to 0.
 *
 * Return: success (0) or failure (errno value)
 */
int hdd_set_tdls_scan_type(struct hdd_context *hdd_ctx, int val)
{
	if ((val != 0) && (val != 1)) {
		hdd_err("Incorrect value of tdls scan type: %d", val);
		return -EINVAL;
	}

	hdd_ctx->config->enable_tdls_scan = val;
	return 0;
}

/**
 * wlan_hdd_tdls_antenna_switch() - Dynamic TDLS antenna  switch 1x1 <-> 2x2
 * antenna mode in standalone station
 * @hdd_ctx: Pointer to hdd contex
 * @adapter: Pointer to hdd adapter
 *
 * Return: 0 if success else non zero
 */
int wlan_hdd_tdls_antenna_switch(struct hdd_context *hdd_ctx,
				 struct hdd_adapter *adapter,
				 uint32_t mode)
{
	if (hdd_ctx->tdls_umac_comp_active)
		return wlan_tdls_antenna_switch(adapter->vdev, mode);

	return 0;
}

QDF_STATUS hdd_tdls_register_peer(void *userdata, uint32_t vdev_id,
				  const uint8_t *mac, uint16_t sta_id,
				  uint8_t qos)
{
	struct hdd_adapter *adapter;
	struct hdd_context *hddctx;

	hddctx = userdata;
	if (!hddctx) {
		hdd_err("Invalid hddctx");
		return QDF_STATUS_E_INVAL;
	}
	adapter = hdd_get_adapter_by_vdev(hddctx, vdev_id);
	if (!adapter) {
		hdd_err("Invalid adapter");
		return QDF_STATUS_E_FAILURE;
	}

	return hdd_roam_register_tdlssta(adapter, mac, sta_id, qos);
}

QDF_STATUS hdd_tdls_deregister_peer(void *userdata, uint32_t vdev_id,
				    uint8_t sta_id)
{
	struct hdd_adapter *adapter;
	struct hdd_context *hddctx;

	hddctx = userdata;
	if (!hddctx) {
		hdd_err("Invalid hddctx");
		return QDF_STATUS_E_INVAL;
	}
	adapter = hdd_get_adapter_by_vdev(hddctx, vdev_id);
	if (!adapter) {
		hdd_err("Invalid adapter");
		return QDF_STATUS_E_FAILURE;
	}

	return hdd_roam_deregister_tdlssta(adapter, sta_id);
}

/**
 * wlan_hdd_change_tdls_mode - Change TDLS mode
 * @data: void pointer
 *
 * Return: None
 */
void wlan_hdd_change_tdls_mode(void *data)
{
	hdd_context_t *hdd_ctx = (hdd_context_t *)data;

	if (hdd_ctx->tdls_mode == eTDLS_SUPPORT_NOT_ENABLED) {
		hdd_debug("TDLS mode is not enabled, don't change the tdls mode");
		return;
	}
	wlan_hdd_tdls_set_mode(hdd_ctx, hdd_ctx->tdls_mode_last, false,
			       HDD_SET_TDLS_MODE_SOURCE_P2P);
}

void hdd_tdls_notify_p2p_roc(hdd_context_t *hdd_ctx,
				enum tdls_concerned_external_events event)
{
	enum tdls_support_mode tdls_mode;
	uint16_t connectedTdlsPeers;
	bool buf_sta, enable_tdls_scan;

	qdf_mc_timer_stop(&hdd_ctx->tdls_source_timer);

	if (eTDLS_SUPPORT_NOT_ENABLED == hdd_ctx->tdls_mode) {
		hdd_debug("TDLS mode is not enabled continue with roc");
		return;
	}

	if (event == P2P_ROC_START) {
		tdls_mode = eTDLS_SUPPORT_DISABLED;
		wlan_hdd_tdls_set_mode(hdd_ctx, tdls_mode, false,
				HDD_SET_TDLS_MODE_SOURCE_P2P);

		connectedTdlsPeers = hdd_ctx->connected_peer_count;
		if (!connectedTdlsPeers)
			goto start_timer;


		enable_tdls_scan =
			wlan_hdd_tdls_check_enable_tdls_scan(hdd_ctx);

		hdd_debug("enable_tdls_scan %d", enable_tdls_scan);

		if (enable_tdls_scan) {
			hdd_debug("Do not teardown tdls links");
			goto start_timer;
		}

		mutex_lock(&hdd_ctx->tdls_lock);
		buf_sta = wlan_hdd_tdls_check_peer_buf_capable(hdd_ctx,
				connectedTdlsPeers);
		mutex_unlock(&hdd_ctx->tdls_lock);

		hdd_debug("buf_sta %d, connected peers %d, sleep sta %d",
				buf_sta, connectedTdlsPeers,
				hdd_ctx->config->fEnableTDLSSleepSta);

		if (!buf_sta) {
			hdd_debug("teardown tdls links");
			wlan_hdd_tdls_disable_offchan_and_teardown_links(
					hdd_ctx, false);
		}
	}

start_timer:
	qdf_mc_timer_start(&hdd_ctx->tdls_source_timer,
			   hdd_ctx->config->tdls_enable_defer_time);
}

void process_rx_tdls_disc_resp_frame(hdd_adapter_t *adapter,
				     uint8_t *peer_addr, int8_t rx_rssi)
{
	hdd_debug("[TDLS] TDLS Discovery Response,"
		  MAC_ADDRESS_STR " RSSI[%d] <--- OTA",
		  MAC_ADDR_ARRAY(peer_addr), rx_rssi);

	wlan_hdd_tdls_set_rssi(adapter, peer_addr, rx_rssi);
	wlan_hdd_tdls_recv_discovery_resp(adapter, peer_addr);
	cds_tdls_tx_rx_mgmt_event(SIR_MAC_ACTION_TDLS,
				  SIR_MAC_ACTION_RX, SIR_MAC_MGMT_ACTION,
				  WLAN_HDD_PUBLIC_ACTION_TDLS_DISC_RESP,
				  peer_addr);
}

void hdd_tdls_notify_hw_mode_change(bool is_dbs_hw_mode)
{
	hdd_context_t *hdd_ctx;
	v_CONTEXT_t g_context;
	enum tdls_support_mode tdls_mode;
	hdd_adapter_t *temp_adapter;

	g_context = cds_get_global_context();

	if (!g_context)
		return;

	hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);

	if (!hdd_ctx)
		return;

	mutex_lock(&hdd_ctx->tdls_lock);
	if (is_dbs_hw_mode)
		hdd_ctx->enable_tdls_in_fw = false;
	else
		hdd_ctx->enable_tdls_in_fw = true;
	mutex_unlock(&hdd_ctx->tdls_lock);

	if (hdd_ctx->tdls_mode == eTDLS_SUPPORT_NOT_ENABLED && is_dbs_hw_mode) {
		hdd_debug("TDLS mode is not enabled continue with hw mode change");
		return;
	}

	if (is_dbs_hw_mode) {
		hdd_debug("hw mode is DBS");
		wlan_hdd_tdls_set_mode(hdd_ctx,
				       eTDLS_SUPPORT_DISABLED,
				       false,
				       HDD_SET_TDLS_MODE_SOURCE_POLICY_MGR);
		return;
	}

	/* if tdls was enabled before dbs, re-enable tdls mode */
	if (hdd_ctx->tdls_mode_last > eTDLS_SUPPORT_DISABLED) {
		tdls_mode = hdd_ctx->tdls_mode_last;
		goto revert_tdls_mode;
	}

	/* TDLS previous mode is modified by other source, so
	 * assign the default configured mode to TDLS
	 */
	if (false == hdd_ctx->config->fEnableTDLSImplicitTrigger)
		tdls_mode = eTDLS_SUPPORT_EXPLICIT_TRIGGER_ONLY;
	else if (true == hdd_ctx->config->fTDLSExternalControl)
		tdls_mode = eTDLS_SUPPORT_EXTERNAL_CONTROL;
	else
		tdls_mode = eTDLS_SUPPORT_ENABLED;

revert_tdls_mode:
	hdd_debug("hw mode is non DBS, so revert to last tdls mode %d",
					tdls_mode);
	temp_adapter = wlan_hdd_tdls_get_adapter(hdd_ctx);
	if (temp_adapter) {
		mutex_lock(&hdd_ctx->tdls_lock);
		if (hdd_ctx->set_state_info.set_state_cnt == 0) {
			mutex_unlock(&hdd_ctx->tdls_lock);
			hdd_debug("HW mode is changed to Non DBS enable TDLS in FW");
			wlan_hdd_update_tdls_info(temp_adapter, false, false);
		} else {
			mutex_unlock(&hdd_ctx->tdls_lock);
		}
		wlan_hdd_tdls_set_mode(hdd_ctx, tdls_mode, false,
				       HDD_SET_TDLS_MODE_SOURCE_POLICY_MGR);
	}
}

void hdd_tdls_init_completion(hdd_adapter_t *adapter)
{
	init_completion(&adapter->tdls_add_station_comp);
	init_completion(&adapter->tdls_del_station_comp);
	init_completion(&adapter->tdls_mgmt_comp);
	init_completion(&adapter->tdls_link_establish_req_comp);
}
