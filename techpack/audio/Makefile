AUDIO_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(CONFIG_ARCH_SDM845), y)
include $(AUDIO_ROOT)/config/sdm845auto.conf
export
endif
ifeq ($(CONFIG_ARCH_SDM670), y)
include $(AUDIO_ROOT)/config/sdm710auto_static.conf
export
endif
ifeq ($(CONFIG_ARCH_SDXPOORWILLS), y)
include $(AUDIO_ROOT)/config/sdxpoorwillsauto.conf
export
endif

# Use USERINCLUDE when you must reference the UAPI directories only.
USERINCLUDE     += \
                -I$(AUDIO_ROOT)/include/uapi \

# Use LINUXINCLUDE when you must reference the include/ directory.
# Needed to be compatible with the O= option
LINUXINCLUDE    += \
                -I$(AUDIO_ROOT)/include/uapi \
                -I$(AUDIO_ROOT)/include

ifeq ($(CONFIG_ARCH_SDM845), y)
LINUXINCLUDE    += \
                -include $(AUDIO_ROOT)/config/sdm845autoconf.h
endif
ifeq ($(CONFIG_ARCH_SDM670), y)
LINUXINCLUDE    += \
                -include $(AUDIO_ROOT)/config/sdm710autoconf.h
endif
ifeq ($(CONFIG_ARCH_SDXPOORWILLS), y)
LINUXINCLUDE    += \
                -include $(AUDIO_ROOT)/config/sdxpoorwillsautoconf.h
endif

obj-y += asoc/
obj-y += dsp/
obj-y += ipc/
obj-y += soc/
