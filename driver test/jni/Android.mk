LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm

LOCAL_MODULE    := dump_test
LOCAL_SRC_FILES := dump_test.c

LOCAL_CFLAGS += -pie
LOCAL_LDFLAGS += -pie -fPIE

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm

LOCAL_MODULE    := dump_host
LOCAL_SRC_FILES := dump_host.c

LOCAL_CFLAGS += -pie
LOCAL_LDFLAGS += -pie -fPIE

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm

LOCAL_MODULE    := ptrace_trace
LOCAL_SRC_FILES := ptrace_trace.c

LOCAL_LDFLAGS := -static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm

LOCAL_MODULE    := bin_wrapper
LOCAL_SRC_FILES := bin_wrapper.c

LOCAL_LDFLAGS := -static

include $(BUILD_EXECUTABLE)