/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "audio_policy_service_unit_test.h"
#include "audio_policy_server.h"

#include <thread>
#include <memory>
#include <vector>
using namespace testing::ext;

namespace OHOS {
namespace AudioStandard {

const int32_t SYSTEM_ABILITY_ID = 3009;
const bool RUN_ON_CREATE = false;
bool g_hasServerInit = false;

enum PerferredType {
    MEDIA_RENDER = 0,
    CALL_RENDER = 1,
    CALL_CAPTURE = 2,
    RING_RENDER = 3,
    RECORD_CAPTURE = 4,
    TONE_RENDER = 5,
};

void AudioPolicyServiceUnitTest::SetUpTestCase(void)
{
    AUDIO_INFO_LOG("AudioPolicyServiceUnitTest::SetUpTestCase start-end");
}
void AudioPolicyServiceUnitTest::TearDownTestCase(void)
{
    AUDIO_INFO_LOG("AudioPolicyServiceUnitTest::TearDownTestCase start-end");
}
void AudioPolicyServiceUnitTest::SetUp(void)
{
    AUDIO_INFO_LOG("AudioPolicyServiceUnitTest::SetUp start-end");
}
void AudioPolicyServiceUnitTest::TearDown(void)
{
    AUDIO_INFO_LOG("AudioPolicyServiceUnitTest::TearDown start-end");
}

AudioPolicyServer* GetServerPtr()
{
    static AudioPolicyServer server(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    if (!g_hasServerInit) {
        server.OnStart();
        server.OnAddSystemAbility(AUDIO_DISTRIBUTED_SERVICE_ID, "");
#ifdef FEATURE_MULTIMODALINPUT_INPUT
        server.OnAddSystemAbility(MULTIMODAL_INPUT_SERVICE_ID, "");
#endif
        server.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");
        server.OnAddSystemAbility(BLUETOOTH_HOST_SYS_ABILITY_ID, "");
        server.OnAddSystemAbility(ACCESSIBILITY_MANAGER_SERVICE_ID, "");
        server.OnAddSystemAbility(POWER_MANAGER_SERVICE_ID, "");
        server.OnAddSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, "");
        server.audioPolicyService_.SetDefaultDeviceLoadFlag(true);
        g_hasServerInit = true;
    }
    return &server;
}

/**
* @tc.name  : Test GetVolumeGroupType.
* @tc.number: GetVolumeGroupType_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetVolumeGroupType_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetVolumeGroupType_001 GetServerPtr() is not null");
        std::string volumeGroupType = "";
        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_EARPIECE);
        EXPECT_EQ("build-in", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_SPEAKER);
        EXPECT_EQ("build-in", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_BLUETOOTH_A2DP);
        EXPECT_EQ("wireless", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_BLUETOOTH_SCO);
        EXPECT_EQ("wireless", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_WIRED_HEADSET);
        EXPECT_EQ("wired", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_USB_HEADSET);
        EXPECT_EQ("wired", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_DP);
        EXPECT_EQ("wired", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_USB_ARM_HEADSET);
        EXPECT_EQ("wired", volumeGroupType);

        volumeGroupType = GetServerPtr()->audioPolicyService_.GetVolumeGroupType(DEVICE_TYPE_MAX);
        EXPECT_EQ("", volumeGroupType);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetVolumeGroupType_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test CheckActiveOutputDeviceSupportOffload.
* @tc.number: CheckActiveOutputDeviceSupportOffload_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, CheckActiveOutputDeviceSupportOffload_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest CheckActiveOutputDeviceSupportOffload GetServerPtr() is not null");
        bool ret = false;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = "444455556666abcdefzzzzz";
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_REMOTE_CAST;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);

        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = "444455556666abcdefzzzzz";
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);

        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = "444455556666abcdef";
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_REMOTE_CAST;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);

        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = "444455556666abcdef";
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest CheckActiveOutputDeviceSupportOffload_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetStreamMute.
* @tc.number: SetStreamMute_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetStreamMute_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetStreamMute_001 GetServerPtr() is not null");
        //case mute is 1
        AudioStreamType streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        int32_t result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        //case mute is 0
        streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 0);
        EXPECT_EQ(SUCCESS, result);

        streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 0);
        EXPECT_EQ(SUCCESS, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 0);
        EXPECT_EQ(SUCCESS, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 0);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetStreamMute_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetStreamMute.
* @tc.number: GetStreamMute_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetStreamMute_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetStreamMute_001 GetServerPtr() is not null");
        AudioStreamType streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        bool result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(false, result);

        streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(false, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(false, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(false, result);

    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetStreamMute_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetSourceOutputStreamMute.
* @tc.number: SetSourceOutputStreamMute_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetSourceOutputStreamMute_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetSourceOutputStreamMute_001 GetServerPtr() is not null");
        int32_t uid = getuid();
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetSourceOutputStreamMute_001 uid:%{public}d", uid);
        bool setMute = false;
        int32_t result = GetServerPtr()->audioPolicyService_.SetSourceOutputStreamMute(uid, setMute);
        EXPECT_EQ(result, 0);

        setMute = true;
        result = GetServerPtr()->audioPolicyService_.SetSourceOutputStreamMute(uid, setMute);
        EXPECT_EQ(result, 0);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetSourceOutputStreamMute_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HandleRecoveryPreferredDevices.
* @tc.number: HandleRecoveryPreferredDevices_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HandleRecoveryPreferredDevices_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleRecoveryPreferredDevices_001 GetServerPtr() is not null");
        int32_t preferredType = MEDIA_RENDER;
        int32_t deviceType = DEVICE_TYPE_SPEAKER;
        int32_t usageOrSourceType = STREAM_USAGE_MUSIC;
        int32_t result = GetServerPtr()->audioPolicyService_.HandleRecoveryPreferredDevices(
            preferredType, deviceType, usageOrSourceType);
        EXPECT_NE(SUCCESS, result);

        preferredType = CALL_RENDER;
        deviceType = DEVICE_TYPE_MIC;
        usageOrSourceType = STREAM_USAGE_MUSIC;
        result = GetServerPtr()->audioPolicyService_.HandleRecoveryPreferredDevices(
            preferredType, deviceType, usageOrSourceType);
        EXPECT_NE(SUCCESS, result);

        preferredType = RING_RENDER;
        deviceType = DEVICE_TYPE_WIRED_HEADPHONES;
        usageOrSourceType = STREAM_USAGE_MUSIC;
        result = GetServerPtr()->audioPolicyService_.HandleRecoveryPreferredDevices(
            preferredType, deviceType, usageOrSourceType);
        EXPECT_NE(SUCCESS, result);

        preferredType = TONE_RENDER;
        deviceType = DEVICE_TYPE_WIRED_HEADPHONES;
        usageOrSourceType = STREAM_USAGE_MUSIC;
        result = GetServerPtr()->audioPolicyService_.HandleRecoveryPreferredDevices(
            preferredType, deviceType, usageOrSourceType);
        EXPECT_NE(SUCCESS, result);

        preferredType = CALL_CAPTURE;
        deviceType = DEVICE_TYPE_MIC;
        usageOrSourceType = STREAM_USAGE_MUSIC;
        result = GetServerPtr()->audioPolicyService_.HandleRecoveryPreferredDevices(
            preferredType, deviceType, usageOrSourceType);
        EXPECT_NE(SUCCESS, result);

        preferredType = RECORD_CAPTURE;
        deviceType = DEVICE_TYPE_MIC;
        usageOrSourceType = STREAM_USAGE_MUSIC;
        result = GetServerPtr()->audioPolicyService_.HandleRecoveryPreferredDevices(
            preferredType, deviceType, usageOrSourceType);
        EXPECT_NE(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleRecoveryPreferredDevices_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SelectOutputDevice.
* @tc.number: SelectOutputDevice_001
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SelectOutputDevice_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_001 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_FAST;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_001 audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        vector<sptr<AudioDeviceDescriptor>> deviceDescriptorVector;
        deviceDescriptorVector.push_back(audioDeviceDescriptor);

        int32_t result = GetServerPtr()->audioPolicyService_.SelectOutputDevice(
            audioRendererFilter, deviceDescriptorVector);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SelectOutputDevice.
* @tc.number: SelectOutputDevice_002
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SelectOutputDevice_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_002 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_002 audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        vector<sptr<AudioDeviceDescriptor>> deviceDescriptorVector;
        deviceDescriptorVector.push_back(audioDeviceDescriptor);

        int32_t result = GetServerPtr()->audioPolicyService_.SelectOutputDevice(
            audioRendererFilter, deviceDescriptorVector);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SelectOutputDevice.
* @tc.number: SelectOutputDevice_003
* @tc.desc  : Test AudioPolicyServic interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SelectOutputDevice_003, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_003 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_002 audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        audioDeviceDescriptor->connectState_ = VIRTUAL_CONNECTED;
        vector<sptr<AudioDeviceDescriptor>> deviceDescriptorVector;
        deviceDescriptorVector.push_back(audioDeviceDescriptor);

        int32_t result = GetServerPtr()->audioPolicyService_.SelectOutputDevice(
            audioRendererFilter, deviceDescriptorVector);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDevice_003 GetServerPtr() is null");
    }
}
} // namespace AudioStandard
} // namespace OHOS

