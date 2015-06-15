LOCAL_PATH:=$(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := Main.cpp
LOCAL_MODULE := process_dex
LOCAL_C_INCLUDES += \
        dalvik/libdex dalvik/

LOCAL_STATIC_LIBRARIES += \
	libdex liblog libutils  
ifneq ($(strip $(USE_MINGW)),)
LOCAL_STATIC_LIBRARIES +=libz
else
LOCAL_LDLIBS += -lz
endif


LOCAL_WHOLE_STATIC_LIBRARIES := libziparchive-host

LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_EXECUTABLE)

