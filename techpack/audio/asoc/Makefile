# for SDM6xx sound card driver
snd-soc-sdm670-objs := sdm660-common.o
obj-$(CONFIG_SND_SOC_INT_CODEC) += sdm660-internal.o
obj-$(CONFIG_SND_SOC_EXT_CODEC) += sdm660-external.o sdm660-ext-dai-links.o
obj-$(CONFIG_SND_SOC_SDM670) += snd-soc-sdm670.o

# for SDM450 sound card driver
snd-soc-sdm450-objs := msm8952.o
obj-$(CONFIG_SND_SOC_EXT_CODEC_SDM450) += msm8952-slimbus.o msm8952-dai-links.o
obj-$(CONFIG_SND_SOC_SDM450) += snd-soc-sdm450.o

# for MSM8909 sound card driver
snd-soc-msm8909-objs := msm8952.o
obj-$(CONFIG_SND_SOC_BG_8909) += msm_bg.o
obj-$(CONFIG_SND_SOC_8909_DIG_CDC) += msm8909.o
obj-$(CONFIG_SND_SOC_EXT_CODEC_8909) += apq8009-i2s-ext-codec.o
obj-$(CONFIG_SND_SOC_MSM8909) += snd-soc-msm8909.o

#for CPE drivers
snd-soc-cpe-objs := msm-cpe-lsm.o
obj-$(CONFIG_SND_SOC_CPE) += snd-soc-cpe.o

# for MSM8998 sound card driver
snd-soc-msm8998-objs := msm8998.o
obj-$(CONFIG_SND_SOC_MACHINE_MSM8998) += snd-soc-msm8998.o

# for SDM845 sound card driver
snd-soc-sdm845-objs := sdm845.o
obj-$(CONFIG_SND_SOC_MACHINE_SDM845) += snd-soc-sdm845.o

# for SDXPOORWILLS sound card driver
snd-soc-sdxpoorwills-objs := sdxpoorwills.o
obj-$(CONFIG_SND_SOC_MACHINE_SDXPOORWILLS) += snd-soc-sdxpoorwills.o

snd-soc-qdsp6v2-objs += msm-dai-q6-v2.o msm-pcm-q6-v2.o \
            msm-pcm-routing-v2.o msm-compress-q6-v2.o \
            msm-pcm-afe-v2.o msm-pcm-voip-v2.o \
            msm-pcm-voice-v2.o msm-dai-q6-hdmi-v2.o \
            msm-lsm-client.o msm-pcm-host-voice-v2.o \
            msm-audio-effects-q6-v2.o msm-pcm-loopback-v2.o \
            msm-dai-slim.o msm-transcode-loopback-q6-v2.o msm-pcm-q6-noirq.o \
            msm-pcm-hostless.o msm-dai-fe.o platform_init.o

obj-$(CONFIG_SND_SOC_QDSP6V2) += snd-soc-qdsp6v2.o msm-pcm-dtmf-v2.o msm-dai-stub-v2.o
obj-$(CONFIG_SND_HWDEP_ROUTING) += msm-pcm-routing-devdep.o
obj-$(CONFIG_DOLBY_DS2) += msm-ds2-dap-config.o
obj-$(CONFIG_DOLBY_LICENSE) += msm-ds2-dap-config.o
obj-$(CONFIG_QTI_PP) += msm-qti-pp-config.o

obj-y += codecs/
