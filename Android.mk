#
# Copyright (C) 2010 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

# libcactus rumtime
include $(CLEAR_VARS)
# prefer arm code due to efficiency critical
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := \
			cactus/branch.c \
			cactus/cactus_be.c \
			cactus/cactus_log.c \
			cactus/core.c \
			cactus/fd_lookup.c \
			cactus/fw_table.c \
			cactus/gardenia.c \
			cactus/ginkgo.c \
			cactus/ipclite.c \
			cactus/ipclite_client.c \
			cactus/ipclite_server.c \
			cactus/md5.c \
			cactus/msg.c \
			cactus/async_work.c \
			cactus/nfct.c \
			cactus/nfq.c \
			cactus/nfqm.c \
			cactus/nl.c \
			cactus/rpclite.c \
			cactus/rtnl.c \
			cactus/rule.c \
			cactus/port/__set_errno.c \
			cactus/port/linux_syscall.S \
			cactus/sig_handle.c \
			cactus/sock_stat.c \
			cactus/timer.c \
			cactus/uevent.c \
			cactus/util.c \
			cactus/kconf.c

LOCAL_SHARED_LIBRARIES := libc libz

# need to be customized for android
LOCAL_CFLAGS := -O3 -DANDROID_CHANGES -fno-strict-aliasing
LOCAL_C_INCLUDES += $(KERNEL_HEADERS) \
					$(LOCAL_PATH)/cactus \
				 	$(LOCAL_PATH)/cactus/port \
					external/zlib

LOCAL_MODULE := libcactus
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)

# lavender executable
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := lavender.c
LOCAL_SHARED_LIBRARIES := libc libcactus
LOCAL_CFLAGS := -O3 -DANDROID_CHANGES -fno-strict-aliasing
LOCAL_C_INCLUDES += $(LOCAL_PATH)/cactus $(LOCAL_PATH)/cactus/port
LOCAL_MODULE := lavender
LOCAL_MODULE_TAGS := eng
include $(BUILD_EXECUTABLE)

# libdesert, the cactus client library
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES :=  desert.c  \
					ipclite.c  \
					ipclite_client.c  \
					rpclite.c

LOCAL_SHARED_LIBRARIES := libc
LOCAL_CFLAGS := -O3 -DANDROID_CHANGES  -fno-strict-aliasing
LOCAL_C_INCLUDES += $(KERNEL_HEADERS) $(LOCAL_PATH)/cactus $(LOCAL_PATH)/cactus/port
LOCAL_MODULE := libdesert
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)

# lotus, the lavender client cli
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := lotus.c
LOCAL_CFLAGS := -O3 -DANDROID_CHANGES -fno-strict-aliasing
LOCAL_SHARED_LIBRARIES := libc libdesert
LOCAL_C_INCLUDES += $(LOCAL_PATH)/cactus $(LOCAL_PATH)/cactus/port
LOCAL_MODULE := lotus
LOCAL_MODULE_TAGS := eng
include $(BUILD_EXECUTABLE)

# javender, the jave binding jni library
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := javender/jni/jni_javender.c
LOCAL_SHARED_LIBRARIES := libdesert libcutils libnativehelper
LOCAL_CFLAGS := -O3 -DANDROID_CHANGES -fno-strict-aliasing
LOCAL_C_INCLUDES += $(LOCAL_PATH)/cactus $(LOCAL_PATH)/cactus/port
LOCAL_MODULE := libjavender
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)

# javender, the jave binding library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(call all-java-files-under, javender)
LOCAL_MODULE := javender
LOCAL_MODULE_TAGS := eng
include $(BUILD_STATIC_JAVA_LIBRARY)

# avender_makefile := $(call all-named-subdir-makefiles, Avender)
# include $(avender_makefile)
