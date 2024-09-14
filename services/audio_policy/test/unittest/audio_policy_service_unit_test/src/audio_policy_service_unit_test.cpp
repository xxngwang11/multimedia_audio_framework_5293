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
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = LOCAL_NETWORK_ID + "xyz";
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_REMOTE_CAST;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);

        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = LOCAL_NETWORK_ID + "xyz";
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);

        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = LOCAL_NETWORK_ID;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_REMOTE_CAST;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(false, ret);

        GetServerPtr()->audioPolicyService_.currentActiveDevice_.networkId_ = LOCAL_NETWORK_ID;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        ret = GetServerPtr()->audioPolicyService_.CheckActiveOutputDeviceSupportOffload();
        EXPECT_EQ(true, ret);
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
        // case STREAM_MUSIC and DEVICE_TYPE_BLUETOOTH_A2DP
        AudioStreamType streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        DeviceStreamInfo audioStreamInfo = {SAMPLE_RATE_48000, ENCODING_PCM, SAMPLE_S16LE, STEREO};
        A2dpDeviceConfigInfo configInfo = {audioStreamInfo, true, 1, false};
        GetServerPtr()->audioPolicyService_.connectedA2dpDeviceMap_.insert(make_pair("aabbcc", configInfo));
        GetServerPtr()->audioPolicyService_.activeBTDevice_ = "aabbcc";
        int32_t result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 0);
        EXPECT_EQ(SUCCESS, result);

        GetServerPtr()->audioPolicyService_.activeBTDevice_ = "xxyyzz";
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        GetServerPtr()->audioPolicyService_.activeBTDevice_ = "aabbcc";
        A2dpDeviceConfigInfo configInfo2 = {audioStreamInfo, false, 1, false};
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        A2dpDeviceConfigInfo configInfo3 = {audioStreamInfo, true, 1, false};
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        // case STREAM_MUSIC and DEVICE_TYPE_SPEAKER
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        // case STREAM_MEDIA and DEVICE_TYPE_BLUETOOTH_A2DP
        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
        EXPECT_EQ(SUCCESS, result);

        // case STREAM_MEDIA and DEVICE_TYPE_SPEAKER
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.SetStreamMute(streamType, 1);
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
        EXPECT_EQ(true, result);

        streamType = STREAM_MUSIC;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(true, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(true, result);

        streamType = STREAM_MEDIA;
        GetServerPtr()->audioPolicyService_.currentActiveDevice_.deviceType_ = DEVICE_TYPE_SPEAKER;
        result = GetServerPtr()->audioPolicyService_.GetStreamMute(streamType);
        EXPECT_EQ(true, result);

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
        audioRendererFilter->uid = -1;
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
        EXPECT_EQ(ERR_INVALID_OPERATION, result);
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
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_SCO;
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

/**
* @tc.name  : Test SelectOutputDeviceByFilterInner.
* @tc.number: SelectOutputDeviceByFilterInner_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SelectOutputDeviceByFilterInner_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDeviceByFilterInner_001 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        vector<sptr<AudioDeviceDescriptor>> deviceDescriptorVector;
        deviceDescriptorVector.push_back(audioDeviceDescriptor);

        int32_t result = GetServerPtr()->audioPolicyService_.SelectOutputDeviceByFilterInner(
            audioRendererFilter, deviceDescriptorVector);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDeviceByFilterInner_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SelectOutputDeviceByFilterInner.
* @tc.number: SelectOutputDeviceByFilterInner_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SelectOutputDeviceByFilterInner_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDeviceByFilterInner_002 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_SCO;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        audioDeviceDescriptor->connectState_ = VIRTUAL_CONNECTED;
        vector<sptr<AudioDeviceDescriptor>> deviceDescriptorVector;
        deviceDescriptorVector.push_back(audioDeviceDescriptor);

        int32_t result = GetServerPtr()->audioPolicyService_.SelectOutputDeviceByFilterInner(
            audioRendererFilter, deviceDescriptorVector);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDeviceByFilterInner_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SelectOutputDeviceByFilterInner.
* @tc.number: SelectOutputDeviceByFilterInner_003
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SelectOutputDeviceByFilterInner_003, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDeviceByFilterInner_003 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_WIRED_HEADPHONES;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        vector<sptr<AudioDeviceDescriptor>> deviceDescriptorVector;
        deviceDescriptorVector.push_back(audioDeviceDescriptor);

        int32_t result = GetServerPtr()->audioPolicyService_.SelectOutputDeviceByFilterInner(
            audioRendererFilter, deviceDescriptorVector);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SelectOutputDeviceByFilterInner_003 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test FilterSinkInputs.
* @tc.number: FilterSinkInputs_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, FilterSinkInputs_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest FilterSinkInputs_001 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;
        bool moveAll = true;
        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.FilterSinkInputs(audioRendererFilter, moveAll);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest FilterSinkInputs_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test FilterSinkInputs.
* @tc.number: FilterSinkInputs_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, FilterSinkInputs_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest FilterSinkInputs_002 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;
        bool moveAll = false;

        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.FilterSinkInputs(audioRendererFilter, moveAll);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest FilterSinkInputs_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test RememberRoutingInfo.
* @tc.number: RememberRoutingInfo_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, RememberRoutingInfo_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest RememberRoutingInfo_001 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        audioDeviceDescriptor->networkId_ = LOCAL_NETWORK_ID;

        int32_t result = GetServerPtr()->audioPolicyService_.RememberRoutingInfo(
            audioRendererFilter, audioDeviceDescriptor);
        EXPECT_EQ(SUCCESS, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest RememberRoutingInfo_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test RememberRoutingInfo.
* @tc.number: RememberRoutingInfo_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, RememberRoutingInfo_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest RememberRoutingInfo_002 GetServerPtr() is not null");
        sptr<AudioRendererFilter> audioRendererFilter = new(std::nothrow) AudioRendererFilter();
        audioRendererFilter->uid = getuid();
        audioRendererFilter->rendererInfo.rendererFlags = STREAM_FLAG_NORMAL;
        audioRendererFilter->rendererInfo.streamUsage = STREAM_USAGE_MUSIC;

        sptr<AudioDeviceDescriptor> audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (audioDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest audioDeviceDescriptor is null");
        }
        audioDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        audioDeviceDescriptor->networkId_ = LOCAL_NETWORK_ID + "xyz";

        int32_t result = GetServerPtr()->audioPolicyService_.RememberRoutingInfo(
            audioRendererFilter, audioDeviceDescriptor);
        EXPECT_EQ(ERR_INVALID_PARAM, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest RememberRoutingInfo_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test MoveToRemoteOutputDevice.
* @tc.number: MoveToRemoteOutputDevice_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, MoveToRemoteOutputDevice_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest MoveToRemoteOutputDevice_001 GetServerPtr() is not null");
        SinkInput sinkInput = {};
        sinkInput.streamId = 123;
        sinkInput.streamType = STREAM_MUSIC;
        sinkInput.uid = getuid();
        sinkInput.pid = getpid();
        vector<SinkInput> sinkInputs;
        sinkInputs.push_back(sinkInput);

        sptr<AudioDeviceDescriptor> remoteDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (remoteDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest remoteDeviceDescriptor is null");
        }
        remoteDeviceDescriptor->deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        remoteDeviceDescriptor->deviceRole_ = DeviceRole::OUTPUT_DEVICE;
        remoteDeviceDescriptor->networkId_ = LOCAL_NETWORK_ID + "xyz";

        int32_t result = GetServerPtr()->audioPolicyService_.MoveToRemoteOutputDevice(
            sinkInputs, remoteDeviceDescriptor);
        EXPECT_EQ(ERR_INVALID_PARAM, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest MoveToRemoteOutputDevice_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test MoveToRemoteOutputDevice.
* @tc.number: MoveToRemoteOutputDevice_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, MoveToRemoteOutputDevice_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest MoveToRemoteOutputDevice_002 GetServerPtr() is not null");
        SinkInput sinkInput = {};
        sinkInput.streamId = 123;
        sinkInput.streamType = STREAM_MUSIC;
        sinkInput.uid = getuid();
        sinkInput.pid = getpid();
        vector<SinkInput> sinkInputs;
        sinkInputs.push_back(sinkInput);

        sptr<AudioDeviceDescriptor> remoteDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (remoteDeviceDescriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest remoteDeviceDescriptor is null");
        }
        remoteDeviceDescriptor->deviceType_ = DEVICE_TYPE_MIC;
        remoteDeviceDescriptor->deviceRole_ = DeviceRole::INPUT_DEVICE;
        remoteDeviceDescriptor->networkId_ = LOCAL_NETWORK_ID + "xyz";;

        int32_t result = GetServerPtr()->audioPolicyService_.MoveToRemoteOutputDevice(
            sinkInputs, remoteDeviceDescriptor);
        EXPECT_EQ(ERR_INVALID_PARAM, result);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest MoveToRemoteOutputDevice_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetCaptureDeviceForUsage.
* @tc.number: SetCaptureDeviceForUsage_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetCaptureDeviceForUsage_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_001 GetServerPtr() is not null");
        AudioScene scene = AUDIO_SCENE_PHONE_CALL;
        SourceType srcType = SOURCE_TYPE_VOICE_COMMUNICATION;
        sptr<AudioDeviceDescriptor> descriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (descriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest descriptor is null");
        }
        descriptor->deviceType_ = DEVICE_TYPE_MIC;
        descriptor->deviceRole_ = DeviceRole::INPUT_DEVICE;
        descriptor->networkId_ = LOCAL_NETWORK_ID;

        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.SetCaptureDeviceForUsage(scene, srcType, descriptor);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetCaptureDeviceForUsage.
* @tc.number: SetCaptureDeviceForUsage_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetCaptureDeviceForUsage_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_002 GetServerPtr() is not null");
        AudioScene scene = AUDIO_SCENE_PHONE_CHAT;
        SourceType srcType = SOURCE_TYPE_VOICE_COMMUNICATION;
        sptr<AudioDeviceDescriptor> descriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (descriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest descriptor is null");
        }
        descriptor->deviceType_ = DEVICE_TYPE_MIC;
        descriptor->deviceRole_ = DeviceRole::INPUT_DEVICE;
        descriptor->networkId_ = LOCAL_NETWORK_ID;

        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.SetCaptureDeviceForUsage(scene, srcType, descriptor);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetCaptureDeviceForUsage.
* @tc.number: SetCaptureDeviceForUsage_003
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetCaptureDeviceForUsage_003, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_003 GetServerPtr() is not null");
        AudioScene scene = AUDIO_SCENE_VOICE_RINGING;
        SourceType srcType = SOURCE_TYPE_VOICE_COMMUNICATION;
        sptr<AudioDeviceDescriptor> descriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (descriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest descriptor is null");
        }
        descriptor->deviceType_ = DEVICE_TYPE_MIC;
        descriptor->deviceRole_ = DeviceRole::INPUT_DEVICE;
        descriptor->networkId_ = LOCAL_NETWORK_ID;

        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.SetCaptureDeviceForUsage(scene, srcType, descriptor);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_003 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetCaptureDeviceForUsage.
* @tc.number: SetCaptureDeviceForUsage_004
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetCaptureDeviceForUsage_004, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_004 GetServerPtr() is not null");
        AudioScene scene = AUDIO_SCENE_VOICE_RINGING;
        SourceType srcType = SOURCE_TYPE_VOICE_MESSAGE;
        sptr<AudioDeviceDescriptor> descriptor = new(std::nothrow) AudioDeviceDescriptor();
        if (descriptor == nullptr) {
            AUDIO_INFO_LOG("AudioPolicyServiceUnitTest descriptor is null");
        }
        descriptor->deviceType_ = DEVICE_TYPE_MIC;
        descriptor->deviceRole_ = DeviceRole::INPUT_DEVICE;
        descriptor->networkId_ = LOCAL_NETWORK_ID;

        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.SetCaptureDeviceForUsage(scene, srcType, descriptor);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetCaptureDeviceForUsage_004 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetSinkPortName.
* @tc.number: GetSinkPortName_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetSinkPortName_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetSinkPortName_001 GetServerPtr() is not null");
        InternalDeviceType deviceType = DEVICE_TYPE_NONE;
        AudioPipeType pipeType = PIPE_TYPE_UNKNOWN;
        string retPortName = "";
        // case1 InternalDeviceType::DEVICE_TYPE_BLUETOOTH_A2DP
        deviceType = DEVICE_TYPE_BLUETOOTH_A2DP;
        GetServerPtr()->audioPolicyService_.a2dpOffloadFlag_ = A2DP_OFFLOAD;
        pipeType = PIPE_TYPE_OFFLOAD;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(BLUETOOTH_SPEAKER, retPortName);

        pipeType = PIPE_TYPE_MULTICHANNEL;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(BLUETOOTH_SPEAKER, retPortName);

        pipeType = PIPE_TYPE_DIRECT_MUSIC;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(BLUETOOTH_SPEAKER, retPortName);

        GetServerPtr()->audioPolicyService_.a2dpOffloadFlag_ = A2DP_NOT_OFFLOAD;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(BLUETOOTH_SPEAKER, retPortName);

        // case 2 InternalDeviceType::DEVICE_TYPE_EARPIECE
        deviceType = DEVICE_TYPE_EARPIECE;
        pipeType = PIPE_TYPE_OFFLOAD;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(OFFLOAD_PRIMARY_SPEAKER, retPortName);

        // case 3 InternalDeviceType::DEVICE_TYPE_SPEAKER
        deviceType = DEVICE_TYPE_SPEAKER;
        pipeType = PIPE_TYPE_MULTICHANNEL;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(MCH_PRIMARY_SPEAKER, retPortName);

        // case 4 InternalDeviceType::DEVICE_TYPE_WIRED_HEADSET
        deviceType = DEVICE_TYPE_WIRED_HEADSET;
        pipeType = PIPE_TYPE_NORMAL_IN;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(PRIMARY_SPEAKER, retPortName);

    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetSinkPortName_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetSinkPortName.
* @tc.number: GetSinkPortName_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetSinkPortName_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetSinkPortName_002 GetServerPtr() is not null");
        InternalDeviceType deviceType = DEVICE_TYPE_NONE;
        AudioPipeType pipeType = PIPE_TYPE_UNKNOWN;
        string retPortName = "";
        // case 5 InternalDeviceType::DEVICE_TYPE_WIRED_HEADPHONES
        deviceType = DEVICE_TYPE_WIRED_HEADPHONES;
        pipeType = PIPE_TYPE_OFFLOAD;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(OFFLOAD_PRIMARY_SPEAKER, retPortName);
        // case 6 InternalDeviceType::DEVICE_TYPE_USB_HEADSET
        deviceType = DEVICE_TYPE_USB_HEADSET;
        pipeType = PIPE_TYPE_MULTICHANNEL;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(MCH_PRIMARY_SPEAKER, retPortName);
        // case 7 InternalDeviceType::DEVICE_TYPE_BLUETOOTH_SCO
        deviceType = DEVICE_TYPE_BLUETOOTH_SCO;
        pipeType = PIPE_TYPE_NORMAL_IN;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(PRIMARY_SPEAKER, retPortName);
        // case 8 InternalDeviceType::DEVICE_TYPE_USB_ARM_HEADSET
        deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(USB_SPEAKER, retPortName);
        // case 9 InternalDeviceType::DEVICE_TYPE_DP
        deviceType = DEVICE_TYPE_DP;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(DP_SINK, retPortName);
        // case 10 InternalDeviceType::DEVICE_TYPE_FILE_SINK
        deviceType = DEVICE_TYPE_FILE_SINK;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(FILE_SINK, retPortName);
        // case 11 InternalDeviceType::DEVICE_TYPE_REMOTE_CAST
        deviceType = DEVICE_TYPE_REMOTE_CAST;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(REMOTE_CAST_INNER_CAPTURER_SINK_NAME, retPortName);
        // case 12 InternalDeviceType::DEVICE_TYPE_NONE
        deviceType = DEVICE_TYPE_NONE;
        retPortName = GetServerPtr()->audioPolicyService_.GetSinkPortName(deviceType, pipeType);
        EXPECT_EQ(PORT_NONE, retPortName);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetSinkPortName_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetSourcePortName.
* @tc.number: GetSourcePortName_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetSourcePortName_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetSourcePortName_001 GetServerPtr() is not null");
        InternalDeviceType deviceType = DEVICE_TYPE_NONE;
        string retPortName = "";

        deviceType = DEVICE_TYPE_MIC;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(PRIMARY_MIC, retPortName);

        deviceType = DEVICE_TYPE_USB_HEADSET;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(PRIMARY_MIC, retPortName);

        deviceType = DEVICE_TYPE_BLUETOOTH_SCO;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(PRIMARY_MIC, retPortName);

        deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(USB_MIC, retPortName);

        deviceType = DEVICE_TYPE_WAKEUP;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(PRIMARY_WAKEUP, retPortName);

        deviceType = DEVICE_TYPE_FILE_SOURCE;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(FILE_SOURCE, retPortName);

        deviceType = DEVICE_TYPE_MAX;
        retPortName = GetServerPtr()->audioPolicyService_.GetSourcePortName(deviceType);
        EXPECT_EQ(PORT_NONE, retPortName);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetSourcePortName_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test ConstructRemoteAudioModuleInfo.
* @tc.number: ConstructRemoteAudioModuleInfo_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, ConstructRemoteAudioModuleInfo_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest ConstructRemoteAudioModuleInfo_001 GetServerPtr() is not null");
        string networkId = "";
        DeviceRole deviceRole = DEVICE_ROLE_NONE;
        DeviceType deviceType = DEVICE_TYPE_NONE;
        AudioModuleInfo audioModuleInforet = {};

        networkId = REMOTE_NETWORK_ID;
        deviceRole = OUTPUT_DEVICE;
        deviceType = DEVICE_TYPE_MIC;
        audioModuleInforet = GetServerPtr()->audioPolicyService_.ConstructRemoteAudioModuleInfo(
            networkId, deviceRole, deviceType);
        EXPECT_EQ("48000", audioModuleInforet.rate);

        networkId = REMOTE_NETWORK_ID;
        deviceRole = INPUT_DEVICE;
        deviceType = DEVICE_TYPE_BLUETOOTH_A2DP;
        audioModuleInforet = GetServerPtr()->audioPolicyService_.ConstructRemoteAudioModuleInfo(
            networkId, deviceRole, deviceType);
        EXPECT_EQ("48000", audioModuleInforet.rate);

        networkId = REMOTE_NETWORK_ID;
        deviceRole = DEVICE_ROLE_MAX;
        deviceType = DEVICE_TYPE_SPEAKER;
        audioModuleInforet = GetServerPtr()->audioPolicyService_.ConstructRemoteAudioModuleInfo(
            networkId, deviceRole, deviceType);
        EXPECT_EQ("48000", audioModuleInforet.rate);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest ConstructRemoteAudioModuleInfo_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test ActivateNewDevice.
* @tc.number: ActivateNewDevice_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, ActivateNewDevice_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest ActivateNewDevice_001 GetServerPtr() is not null");
        string networkId = "";
        DeviceType deviceType = DEVICE_TYPE_NONE;
        bool isRemote = false;
        int32_t ret = SUCCESS;

        networkId = LOCAL_NETWORK_ID;
        deviceType = DEVICE_TYPE_MIC;
        isRemote = true;
        ret = GetServerPtr()->audioPolicyService_.ActivateNewDevice(networkId, deviceType, isRemote);
        EXPECT_EQ(SUCCESS, ret);

        networkId = REMOTE_NETWORK_ID;
        deviceType = DEVICE_TYPE_USB_HEADSET;
        isRemote = false;
        ret = GetServerPtr()->audioPolicyService_.ActivateNewDevice(networkId, deviceType, isRemote);
        EXPECT_EQ(SUCCESS, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest ActivateNewDevice_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test SetWakeUpAudioCapturer.
* @tc.number: SetWakeUpAudioCapturer_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, SetWakeUpAudioCapturer_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetWakeUpAudioCapturer_001 GetServerPtr() is not null");
        AudioStreamInfo audioStreamInfo;
        audioStreamInfo.samplingRate = AudioSamplingRate::SAMPLE_RATE_48000;
        audioStreamInfo.encoding = AudioEncodingType::ENCODING_PCM;
        audioStreamInfo.format = AudioSampleFormat::SAMPLE_S16LE;
        audioStreamInfo.channels = AudioChannel::MONO;

        InternalAudioCapturerOptions capturerOptions;
        capturerOptions.streamInfo = audioStreamInfo;

        GetServerPtr()->audioPolicyService_.isAdapterInfoMap_.store(false);
        int32_t ret = GetServerPtr()->audioPolicyService_.SetWakeUpAudioCapturer(capturerOptions);
        EXPECT_EQ(ERROR, ret);

        GetServerPtr()->audioPolicyService_.isAdapterInfoMap_.store(true);
        ret = GetServerPtr()->audioPolicyService_.SetWakeUpAudioCapturer(capturerOptions);
        EXPECT_EQ(ERROR, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest SetWakeUpAudioCapturer_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetDevices.
* @tc.number: GetDevices_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetDevices_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDevices_001 GetServerPtr() is not null");
        EXPECT_NO_THROW(
            DeviceFlag deviceFlag = OUTPUT_DEVICES_FLAG;
            sptr ptr(new AudioDeviceDescriptor());
            ptr = nullptr;
            GetServerPtr()->audioPolicyService_.connectedDevices_.push_back(ptr);
            GetServerPtr()->audioPolicyService_.GetDevices(deviceFlag);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDevices_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetPreferredOutputDeviceDescriptors.
* @tc.number: GetPreferredOutputDeviceDescriptors_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetPreferredOutputDeviceDescriptors_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetPreferredOutputDeviceDescriptors_001 GetServerPtr() is not null");
        EXPECT_NO_THROW(
            AudioRendererInfo rendererInfo;
            rendererInfo.streamUsage = STREAM_USAGE_INVALID;
            string networkId = REMOTE_NETWORK_ID;
            GetServerPtr()->audioPolicyService_.GetPreferredOutputDeviceDescriptors(rendererInfo, networkId);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetPreferredOutputDeviceDescriptors_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetDeviceRole.
* @tc.number: GetDeviceRole_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetDeviceRole_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDeviceRole_001 GetServerPtr() is not null");
        DeviceRole ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_EARPIECE);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_SPEAKER);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_BLUETOOTH_SCO);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_BLUETOOTH_A2DP);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_WIRED_HEADSET);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_WIRED_HEADPHONES);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_USB_HEADSET);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_DP);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_USB_ARM_HEADSET);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_REMOTE_CAST);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_MIC);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_WAKEUP);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(DEVICE_TYPE_NONE);
        EXPECT_EQ(DEVICE_ROLE_NONE, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDeviceRole_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetDeviceRole.
* @tc.number: GetDeviceRole_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetDeviceRole_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDeviceRole_002 GetServerPtr() is not null");
        DeviceRole ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(ROLE_SINK);
        EXPECT_EQ(OUTPUT_DEVICE, ret);
        
        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(ROLE_SOURCE);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole("none");
        EXPECT_EQ(DEVICE_ROLE_NONE, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDeviceRole_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetDeviceRole.
* @tc.number: GetDeviceRole_003
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetDeviceRole_003, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDeviceRole_003 GetServerPtr() is not null");
        DeviceRole ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_NONE);
        EXPECT_EQ(DEVICE_ROLE_NONE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_SPEAKER);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_HEADSET);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_LINEOUT);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_HDMI);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_USB);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_USB_EXT);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_OUT_DAUDIO_DEFAULT);
        EXPECT_EQ(OUTPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_IN_MIC);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_IN_HS_MIC);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_IN_LINEIN);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_IN_USB_EXT);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(AUDIO_PIN_IN_DAUDIO_DEFAULT);
        EXPECT_EQ(INPUT_DEVICE, ret);

        ret = GetServerPtr()->audioPolicyService_.GetDeviceRole(static_cast<AudioPin>(AUDIO_PIN_IN_DAUDIO_DEFAULT + 1));
        EXPECT_EQ(DEVICE_ROLE_NONE, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetDeviceRole_003 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test GetAudioScene.
* @tc.number: GetAudioScene_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, GetAudioScene_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetAudioScene_001 GetServerPtr() is not null");
        bool hasSystemPermission = true;
        AudioScene ret = AUDIO_SCENE_INVALID;
        GetServerPtr()->audioPolicyService_.audioScene_ = AUDIO_SCENE_RINGING;
        ret = GetServerPtr()->audioPolicyService_.GetAudioScene(hasSystemPermission);
        EXPECT_EQ(AUDIO_SCENE_DEFAULT, ret);

        hasSystemPermission = false;
        GetServerPtr()->audioPolicyService_.audioScene_ = AUDIO_SCENE_CALL_START;
        ret = GetServerPtr()->audioPolicyService_.GetAudioScene(hasSystemPermission);
        EXPECT_EQ(AUDIO_SCENE_DEFAULT, ret);

        GetServerPtr()->audioPolicyService_.audioScene_ = AUDIO_SCENE_CALL_END;
        ret = GetServerPtr()->audioPolicyService_.GetAudioScene(hasSystemPermission);
        EXPECT_EQ(AUDIO_SCENE_DEFAULT, ret);

        GetServerPtr()->audioPolicyService_.audioScene_ = AUDIO_SCENE_PHONE_CHAT;
        ret = GetServerPtr()->audioPolicyService_.GetAudioScene(hasSystemPermission);
        EXPECT_EQ(AUDIO_SCENE_DEFAULT, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest GetAudioScene_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test UpdateEffectDefaultSink.
* @tc.number: UpdateEffectDefaultSink_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, UpdateEffectDefaultSink_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest UpdateEffectDefaultSink_001 GetServerPtr() is not null");
        EXPECT_NO_THROW(
            GetServerPtr()->audioPolicyService_.UpdateEffectDefaultSink(DEVICE_TYPE_NONE);
        );
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest UpdateEffectDefaultSink_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HasLowLatencyCapability.
* @tc.number: HasLowLatencyCapability_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HasLowLatencyCapability_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HasLowLatencyCapability_001 GetServerPtr() is not null");
        bool ret = false;
        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_NONE, true);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_EARPIECE, false);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_SPEAKER, false);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_WIRED_HEADSET, false);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_WIRED_HEADPHONES, false);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_USB_HEADSET, false);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_DP, false);
        EXPECT_EQ(true, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_BLUETOOTH_SCO, false);
        EXPECT_EQ(false, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_BLUETOOTH_A2DP, false);
        EXPECT_EQ(false, ret);

        ret = GetServerPtr()->audioPolicyService_.HasLowLatencyCapability(DEVICE_TYPE_INVALID, false);
        EXPECT_EQ(false, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HasLowLatencyCapability_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HandleActiveDevice.
* @tc.number: HandleActiveDevice_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HandleActiveDevice_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleActiveDevice_001 GetServerPtr() is not null");
        int32_t ret = SUCCESS;
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_NONE);
        EXPECT_EQ(ERR_OPERATION_FAILED, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_INVALID);
        EXPECT_EQ(ERR_OPERATION_FAILED, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_EARPIECE);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_SPEAKER);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_WIRED_HEADSET);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_WIRED_HEADPHONES);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_BLUETOOTH_SCO);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_BLUETOOTH_A2DP);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_MIC);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_WAKEUP);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_USB_HEADSET);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_DP);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_REMOTE_CAST);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_FILE_SINK);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_FILE_SOURCE);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_EXTERN_CABLE);
        EXPECT_EQ(ERR_OPERATION_FAILED, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_DEFAULT);
        EXPECT_EQ(ERR_OPERATION_FAILED, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_USB_ARM_HEADSET);
        EXPECT_EQ(SUCCESS, ret);
        ret = GetServerPtr()->audioPolicyService_.HandleActiveDevice(DEVICE_TYPE_MAX);
        EXPECT_EQ(ERR_OPERATION_FAILED, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleActiveDevice_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HandleLocalDeviceConnected.
* @tc.number: HandleLocalDeviceConnected_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HandleLocalDeviceConnected_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceConnected_001 GetServerPtr() is not null");
        int32_t ret = SUCCESS;
        AudioDeviceDescriptor updatedDesc;
        updatedDesc.deviceType_ = DEVICE_TYPE_EARPIECE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_SPEAKER;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_WIRED_HEADSET;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_WIRED_HEADPHONES;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_BLUETOOTH_SCO;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        // ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc)
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_MIC;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_WAKEUP;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_USB_HEADSET;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_DP;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(ERROR, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceConnected_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HandleLocalDeviceConnected.
* @tc.number: HandleLocalDeviceConnected_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HandleLocalDeviceConnected_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceConnected_002 GetServerPtr() is not null");
        int32_t ret = SUCCESS;
        AudioDeviceDescriptor updatedDesc;
        updatedDesc.deviceType_ = DEVICE_TYPE_REMOTE_CAST;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_FILE_SINK;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_FILE_SOURCE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_EXTERN_CABLE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_DEFAULT;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_USB_ARM_HEADSET;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(ERROR, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_MAX;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_NONE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_INVALID;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceConnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceConnected_002 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HandleLocalDeviceDisconnected.
* @tc.number: HandleLocalDeviceDisconnected_001
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HandleLocalDeviceDisconnected_001, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceDisconnected_001 GetServerPtr() is not null");
        int32_t ret = SUCCESS;
        AudioDeviceDescriptor updatedDesc;
        updatedDesc.deviceType_ = DEVICE_TYPE_EARPIECE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_SPEAKER;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_WIRED_HEADSET;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_WIRED_HEADPHONES;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_BLUETOOTH_SCO;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_MIC;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_WAKEUP;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_USB_HEADSET;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_DP;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceDisconnected_001 GetServerPtr() is null");
    }
}

/**
* @tc.name  : Test HandleLocalDeviceDisconnected.
* @tc.number: HandleLocalDeviceDisconnected_002
* @tc.desc  : Test AudioPolicyService interfaces.
*/
HWTEST(AudioPolicyServiceUnitTest, HandleLocalDeviceDisconnected_002, TestSize.Level1)
{
    if (GetServerPtr() != nullptr) {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceDisconnected_002 GetServerPtr() is not null");
        int32_t ret = SUCCESS;
        AudioDeviceDescriptor updatedDesc;
        updatedDesc.deviceType_ = DEVICE_TYPE_REMOTE_CAST;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_FILE_SINK;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_FILE_SOURCE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_EXTERN_CABLE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_DEFAULT;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_USB_ARM_HEADSET;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_MAX;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_NONE;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);

        updatedDesc.deviceType_ = DEVICE_TYPE_INVALID;
        ret = GetServerPtr()->audioPolicyService_.HandleLocalDeviceDisconnected(updatedDesc);
        EXPECT_EQ(SUCCESS, ret);
    } else {
        AUDIO_INFO_LOG("AudioPolicyServiceUnitTest HandleLocalDeviceDisconnected_002 GetServerPtr() is null");
    }
}
} // namespace AudioStandard
} // namespace OHOS
