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
#include "audio_policy_service_ext_unit_test.h"
#include "audio_info.h"
#include "audio_policy_server.h"
#include "audio_policy_service.h"
#include "audio_session_info.h"
#include "audio_system_manager.h"
#include <memory>
#include <thread>
#include <vector>

using namespace testing::ext;
using namespace std;
namespace OHOS {
namespace AudioStandard {
const int32_t SYSTEM_ABILITY_ID = 3009;
const bool RUN_ON_CREATE = false;
bool g_isInit = false;
static AudioPolicyServer g_server(SYSTEM_ABILITY_ID, RUN_ON_CREATE);

void AudioPolicyServiceExtUnitTest::SetUpTestCase(void) {}
void AudioPolicyServiceExtUnitTest::TearDownTestCase(void) {}
void AudioPolicyServiceExtUnitTest::SetUp(void) {}
void AudioPolicyServiceExtUnitTest::TearDown(void)
{
    g_server.OnStop();
    g_isInit = false;
}

AudioPolicyServer *GetServerSptr()
{
    if (!g_isInit) {
        g_server.OnStart();
        g_server.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");
        g_server.OnAddSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, "");
        g_server.OnAddSystemAbility(ACCESSIBILITY_MANAGER_SERVICE_ID, "");
        g_server.OnAddSystemAbility(COMMON_EVENT_SERVICE_ID, "");
        g_server.OnAddSystemAbility(AUDIO_DISTRIBUTED_SERVICE_ID, "");
        g_server.OnAddSystemAbility(MULTIMODAL_INPUT_SERVICE_ID, "");
        g_server.OnAddSystemAbility(BLUETOOTH_HOST_SYS_ABILITY_ID, "");
        g_server.OnAddSystemAbility(POWER_MANAGER_SERVICE_ID, "");
        g_server.OnAddSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, "");
        g_server.audioPolicyService_.SetDefaultDeviceLoadFlag(true);
        g_isInit = true;
    }
    return &g_server;
}

/**
 * @tc.name  : Test StreamVolumesDump.
 * @tc.number: StreamVolumesDump_001
 * @tc.desc  : Test StreamVolumesDump interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, StreamVolumesDump_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string dumpString = "666";
    server->AudioVolumeDump(dumpString);
    EXPECT_NE(dumpString, "666");
}

/**
 * @tc.name  : Test AudioStreamDump.
 * @tc.number: AudioStreamDump_001
 * @tc.desc  : Test AudioStreamDump interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, AudioStreamDump_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string dumpString = "666";
    server->AudioStreamDump(dumpString);
    EXPECT_NE(dumpString, "666");
}

/**
 * @tc.name  : Test CheckAudioSessionStrategy.
 * @tc.number: CheckAudioSessionStrategy_001
 * @tc.desc  : Test CheckAudioSessionStrategy interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, CheckAudioSessionStrategy_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    AudioSessionStrategy sessionStrategy;
    sessionStrategy.concurrencyMode = AudioConcurrencyMode::DEFAULT;
    bool ret = server->CheckAudioSessionStrategy(sessionStrategy);
    EXPECT_EQ(ret, true);

    sessionStrategy.concurrencyMode = (AudioConcurrencyMode)666;
    ret = server->CheckAudioSessionStrategy(sessionStrategy);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test LoadSplitModule.
 * @tc.number: LoadSplitModule_001
 * @tc.desc  : Test LoadSplitModule interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, LoadSplitModule_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string splitArgs = "";
    std::string networkId = "";
    int32_t ret = server->audioPolicyService_.LoadSplitModule(splitArgs, networkId);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);

    splitArgs = "test";
    networkId = LOCAL_NETWORK_ID;
    ret = server->audioPolicyService_.LoadSplitModule(splitArgs, networkId);
    EXPECT_EQ(ret, ERR_INVALID_HANDLE);
}

/**
 * @tc.name  : Test HandleA2dpDeviceInOffload.
 * @tc.number: HandleA2dpDeviceInOffload_001
 * @tc.desc  : Test HandleA2dpDeviceInOffload interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, HandleA2dpDeviceInOffload_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    BluetoothOffloadState a2dpOffloadFlag = A2DP_NOT_OFFLOAD;
    int32_t ret = server->audioPolicyService_.HandleA2dpDeviceInOffload(a2dpOffloadFlag);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name  : Test ReconfigureAudioChannel.
 * @tc.number: ReconfigureAudioChannel_001
 * @tc.desc  : Test ReconfigureAudioChannel interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, ReconfigureAudioChannel_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    uint32_t channelCount = 1;
    DeviceType deviceType = DeviceType::DEVICE_TYPE_SPEAKER;
    int32_t ret = server->audioPolicyService_.ReconfigureAudioChannel(channelCount, deviceType);
    EXPECT_EQ(ret, ERROR);

    deviceType = DeviceType::DEVICE_TYPE_FILE_SINK;
    ret = server->audioPolicyService_.ReconfigureAudioChannel(channelCount, deviceType);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test WriteDeviceChangedSysEvents.
 * @tc.number: WriteDeviceChangedSysEvents_001
 * @tc.desc  : Test WriteDeviceChangedSysEvents interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, WriteDeviceChangedSysEvents_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::vector<sptr<AudioDeviceDescriptor>> desc =
        AudioSystemManager::GetInstance()->GetDevices(DeviceFlag::ALL_DEVICES_FLAG);
    bool isConnected = false;
    server->audioPolicyService_.WriteDeviceChangedSysEvents(desc, isConnected);
    EXPECT_EQ(isConnected, false);
}

/**
 * @tc.name  : Test UpdateTrackerDeviceChange.
 * @tc.number: UpdateTrackerDeviceChange_001
 * @tc.desc  : Test UpdateTrackerDeviceChange interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, UpdateTrackerDeviceChange_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::vector<sptr<AudioDeviceDescriptor>> desc =
        AudioSystemManager::GetInstance()->GetDevices(DeviceFlag::ALL_DEVICES_FLAG);
    server->audioPolicyService_.UpdateTrackerDeviceChange(desc);
    EXPECT_TRUE(desc.size() > 0);
}

/**
 * @tc.name  : Test SetAbsVolumeSceneAsync.
 * @tc.number: SetAbsVolumeSceneAsync_001
 * @tc.desc  : Test SetAbsVolumeSceneAsync interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, SetAbsVolumeSceneAsync_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string macAddress = "";
    bool support = false;
    server->audioPolicyService_.SetAbsVolumeSceneAsync(macAddress, support);
    EXPECT_EQ(support, false);
}

/**
 * @tc.name  : Test SetDeviceAbsVolumeSupported.
 * @tc.number: SetDeviceAbsVolumeSupported_001
 * @tc.desc  : Test SetDeviceAbsVolumeSupported interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, SetDeviceAbsVolumeSupported_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string macAddress = "";
    bool support = false;
    int32_t ret = server->audioPolicyService_.SetDeviceAbsVolumeSupported(macAddress, support);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test IsWiredHeadSet.
 * @tc.number: IsWiredHeadSet_001
 * @tc.desc  : Test IsWiredHeadSet interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, IsWiredHeadSet_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    DeviceType deviceType = DeviceType::DEVICE_TYPE_SPEAKER;
    int32_t ret = server->audioPolicyService_.IsWiredHeadSet(deviceType);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name  : Test IsBlueTooth.
 * @tc.number: IsBlueTooth_001
 * @tc.desc  : Test IsBlueTooth interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, IsBlueTooth_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    DeviceType deviceType = DeviceType::DEVICE_TYPE_SPEAKER;
    int32_t ret = server->audioPolicyService_.IsBlueTooth(deviceType);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name  : Test CheckBlueToothActiveMusicTime.
 * @tc.number: CheckBlueToothActiveMusicTime_001
 * @tc.desc  : Test CheckBlueToothActiveMusicTime interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, CheckBlueToothActiveMusicTime_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    int32_t safeVolume = 1;
    server->audioPolicyService_.CheckBlueToothActiveMusicTime(safeVolume);
    EXPECT_EQ(safeVolume, 1);
}

/**
 * @tc.name  : Test CheckWiredActiveMusicTime.
 * @tc.number: CheckWiredActiveMusicTime_001
 * @tc.desc  : Test CheckWiredActiveMusicTime interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, CheckWiredActiveMusicTime_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    int32_t safeVolume = 1;
    server->audioPolicyService_.CheckWiredActiveMusicTime(safeVolume);
    EXPECT_EQ(safeVolume, 1);
}

/**
 * @tc.name  : Test RestoreSafeVolume.
 * @tc.number: RestoreSafeVolume_001
 * @tc.desc  : Test RestoreSafeVolume interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, RestoreSafeVolume_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    AudioStreamType streamType = AudioStreamType::STREAM_RING;
    int32_t safeVolume = 1;
    server->audioPolicyService_.RestoreSafeVolume(streamType, safeVolume);
    EXPECT_EQ(safeVolume, 1);
}

/**
 * @tc.name  : Test CreateCheckMusicActiveThread.
 * @tc.number: CreateCheckMusicActiveThread_001
 * @tc.desc  : Test CreateCheckMusicActiveThread interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, CreateCheckMusicActiveThread_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    server->audioPolicyService_.CreateCheckMusicActiveThread();
}

/**
 * @tc.name  : Test CreateSafeVolumeDialogThread.
 * @tc.number: CreateSafeVolumeDialogThread_001
 * @tc.desc  : Test CreateSafeVolumeDialogThread interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, CreateSafeVolumeDialogThread_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    server->audioPolicyService_.CreateSafeVolumeDialogThread();
}

/**
 * @tc.name  : Test ShowDialog.
 * @tc.number: ShowDialog_001
 * @tc.desc  : Test ShowDialog interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, ShowDialog_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    int32_t ret = server->audioPolicyService_.ShowDialog();
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name  : Test DealWithSafeVolume.
 * @tc.number: DealWithSafeVolume_001
 * @tc.desc  : Test DealWithSafeVolume interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, DealWithSafeVolume_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    int32_t volumeLevel = 5;
    bool isA2dpDevice = true;
    int32_t volumeLevelRet = server->audioPolicyService_.DealWithSafeVolume(volumeLevel, isA2dpDevice);
    EXPECT_EQ(volumeLevelRet, 5);

    isA2dpDevice = false;
    volumeLevelRet = server->audioPolicyService_.DealWithSafeVolume(volumeLevel, isA2dpDevice);
    EXPECT_EQ(volumeLevelRet, 8);

    volumeLevel = 11;
    volumeLevelRet = server->audioPolicyService_.DealWithSafeVolume(volumeLevel, isA2dpDevice);
    EXPECT_EQ(volumeLevelRet, 8);
}

/**
 * @tc.name  : Test HandleAbsBluetoothVolume.
 * @tc.number: HandleAbsBluetoothVolume_001
 * @tc.desc  : Test HandleAbsBluetoothVolume interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, HandleAbsBluetoothVolume_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string macAddress = "";
    int32_t volumeLevel = 10;
    int32_t safeVolumeLevel = server->audioPolicyService_.HandleAbsBluetoothVolume(macAddress, volumeLevel);
    EXPECT_EQ(safeVolumeLevel, 8);

    volumeLevel = 1;
    safeVolumeLevel = server->audioPolicyService_.HandleAbsBluetoothVolume(macAddress, volumeLevel);
    EXPECT_EQ(safeVolumeLevel, 1);
}

/**
 * @tc.name  : Test SetA2dpDeviceVolume.
 * @tc.number: SetA2dpDeviceVolume_001
 * @tc.desc  : Test SetA2dpDeviceVolume interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, SetA2dpDeviceVolume_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    std::string macAddress = "";
    int32_t volumeLevel = 4;
    bool internalCall = false;
    int32_t ret = server->audioPolicyService_.SetA2dpDeviceVolume(macAddress, volumeLevel, internalCall);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test TriggerDeviceChangedCallback.
 * @tc.number: TriggerDeviceChangedCallback_001
 * @tc.desc  : Test TriggerDeviceChangedCallback interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, TriggerDeviceChangedCallback_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    vector<sptr<AudioDeviceDescriptor>> desc =
        AudioSystemManager::GetInstance()->GetDevices(DeviceFlag::ALL_DEVICES_FLAG);
    bool isConnected = false;
    server->audioPolicyService_.TriggerDeviceChangedCallback(desc, isConnected);
    EXPECT_EQ(isConnected, false);
}

/**
 * @tc.name  : Test GetDeviceRole.
 * @tc.number: GetDeviceRole_001
 * @tc.desc  : Test GetDeviceRole interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, GetDeviceRole_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    DeviceType deviceType = DeviceType::DEVICE_TYPE_SPEAKER;
    DeviceRole deviceRole = server->audioPolicyService_.GetDeviceRole(deviceType);
    EXPECT_EQ(deviceRole, DeviceRole::OUTPUT_DEVICE);

    deviceType = DeviceType::DEVICE_TYPE_WAKEUP;
    deviceRole = server->audioPolicyService_.GetDeviceRole(deviceType);
    EXPECT_EQ(deviceRole, DeviceRole::INPUT_DEVICE);

    deviceType = DeviceType::DEVICE_TYPE_DEFAULT;
    deviceRole = server->audioPolicyService_.GetDeviceRole(deviceType);
    EXPECT_EQ(deviceRole, DeviceRole::DEVICE_ROLE_NONE);
}

/**
 * @tc.name  : Test GetDeviceRole.
 * @tc.number: GetDeviceRole_002
 * @tc.desc  : Test GetDeviceRole interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, GetDeviceRole_002, TestSize.Level1)
{
    auto server = GetServerSptr();
    AudioPin pin = AudioPin::AUDIO_PIN_NONE;
    DeviceRole deviceRole = server->audioPolicyService_.GetDeviceRole(pin);
    EXPECT_EQ(deviceRole, DeviceRole::DEVICE_ROLE_NONE);

    pin = AudioPin::AUDIO_PIN_OUT_SPEAKER;
    deviceRole = server->audioPolicyService_.GetDeviceRole(pin);
    EXPECT_EQ(deviceRole, DeviceRole::OUTPUT_DEVICE);

    pin = AudioPin::AUDIO_PIN_IN_MIC;
    deviceRole = server->audioPolicyService_.GetDeviceRole(pin);
    EXPECT_EQ(deviceRole, DeviceRole::INPUT_DEVICE);

    pin = (AudioPin)666;
    deviceRole = server->audioPolicyService_.GetDeviceRole(pin);
    EXPECT_EQ(deviceRole, DeviceRole::DEVICE_ROLE_NONE);
}

/**
 * @tc.name  : Test UpdateInputDeviceInfo.
 * @tc.number: UpdateInputDeviceInfo_001
 * @tc.desc  : Test UpdateInputDeviceInfo interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, UpdateInputDeviceInfo_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    DeviceType deviceType = DeviceType::DEVICE_TYPE_SPEAKER;
    server->audioPolicyService_.UpdateInputDeviceInfo(deviceType);
    EXPECT_EQ(server->audioPolicyService_.currentActiveInputDevice_.deviceType_, DeviceType::DEVICE_TYPE_MIC);

    deviceType = DeviceType::DEVICE_TYPE_FILE_SINK;
    server->audioPolicyService_.UpdateInputDeviceInfo(deviceType);
    EXPECT_EQ(server->audioPolicyService_.currentActiveInputDevice_.deviceType_, DeviceType::DEVICE_TYPE_FILE_SOURCE);

    deviceType = DeviceType::DEVICE_TYPE_USB_ARM_HEADSET;
    server->audioPolicyService_.UpdateInputDeviceInfo(deviceType);
    EXPECT_EQ(server->audioPolicyService_.currentActiveInputDevice_.deviceType_, DeviceType::DEVICE_TYPE_USB_HEADSET);

    deviceType = DeviceType::DEVICE_TYPE_WIRED_HEADSET;
    server->audioPolicyService_.UpdateInputDeviceInfo(deviceType);
    EXPECT_EQ(server->audioPolicyService_.currentActiveInputDevice_.deviceType_, DeviceType::DEVICE_TYPE_WIRED_HEADSET);

    deviceType = (DeviceType)777;
    server->audioPolicyService_.UpdateInputDeviceInfo(deviceType);
    EXPECT_EQ(server->audioPolicyService_.currentActiveInputDevice_.deviceType_, DeviceType::DEVICE_TYPE_WIRED_HEADSET);
}

/**
 * @tc.name  : Test GetDeviceTypeFromPin.
 * @tc.number: GetDeviceTypeFromPin_001
 * @tc.desc  : Test GetDeviceTypeFromPin interfaces.
 */
HWTEST(AudioPolicyServiceExtUnitTest, GetDeviceTypeFromPin_001, TestSize.Level1)
{
    auto server = GetServerSptr();
    AudioPin hdiPin = AudioPin::AUDIO_PIN_NONE;
    DeviceType deviceType = server->audioPolicyService_.GetDeviceTypeFromPin(hdiPin);
    EXPECT_EQ(deviceType, DeviceType::DEVICE_TYPE_DEFAULT);

    hdiPin = AudioPin::AUDIO_PIN_NONE;
    deviceType = server->audioPolicyService_.GetDeviceTypeFromPin(hdiPin);
    EXPECT_EQ(deviceType, DeviceType::DEVICE_TYPE_DEFAULT);

    hdiPin = AudioPin::AUDIO_PIN_NONE;
    deviceType = server->audioPolicyService_.GetDeviceTypeFromPin(hdiPin);
    EXPECT_EQ(deviceType, DeviceType::DEVICE_TYPE_DEFAULT);
}

} // namespace AudioStandard
} // namespace OHOS