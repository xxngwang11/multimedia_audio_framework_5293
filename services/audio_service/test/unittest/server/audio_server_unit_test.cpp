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
#include <gtest/gtest.h>

#include "audio_service_log.h"
#include "audio_errors.h"
#include "audio_server.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace AudioStandard {

class AudioServerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

/**
 * @tc.name  : Test CreatePlaybackCapturerManager API
 * @tc.type  : FUNC
 * @tc.number: CreatePlaybackCapturerManager_001
 * @tc.desc  : Test CreatePlaybackCapturerManager interface using empty case.
 */
HWTEST(AudioServerUnitTest, CreatePlaybackCapturerManager_001, TestSize.Level1)
{
    AUDIO_INFO_LOG("AudioServerUnitTest CreatePlaybackCapturerManager_001 start");
    int32_t systemAbilityId = 100;
    std::shared_ptr<AudioServer> audioServer = std::make_shared<AudioServer>(systemAbilityId, true);
    bool ret = audioServer->CreatePlaybackCapturerManager();
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name  : Test SetIORoutes API
 * @tc.type  : FUNC
 * @tc.number: SetIORoutes_001
 * @tc.desc  : Test SetIORoutes interface using empty case, when type is DEVICE_TYPE_USB_ARM_HEADSET,
                deviceType is DEVICE_TYPE_USB_ARM_HEADSET.
 */
HWTEST(AudioServerUnitTest, SetIORoutes_001, TestSize.Level1)
{
    AUDIO_INFO_LOG("AudioServerUnitTest SetIORoutes_001 start");
    int32_t systemAbilityId = 100;
    std::shared_ptr<AudioServer> audioServer = std::make_shared<AudioServer>(systemAbilityId, true);
    DeviceType type = DEVICE_TYPE_USB_ARM_HEADSET;
    DeviceFlag flag = ALL_DEVICES_FLAG;
    std::vector<DeviceType> deviceTypes;
    DeviceType deviceType = DEVICE_TYPE_USB_ARM_HEADSET;
    deviceTypes.push_back(deviceType);
    BluetoothOffloadState a2dpOffloadFlag = A2DP_OFFLOAD;
    bool ret = audioServer->SetIORoutes(type, flag, deviceTypes, a2dpOffloadFlag);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name  : Test OnAddSystemAbility API
 * @tc.type  : FUNC
 * @tc.number: OnAddSystemAbility_001
 * @tc.desc  : Test OnAddSystemAbility interface using empty case.
 */
HWTEST(AudioServerUnitTest, OnAddSystemAbility_001, TestSize.Level1)
{
    AUDIO_INFO_LOG("AudioServerUnitTest OnAddSystemAbility_001 start");
    int32_t systemAbilityId = 100;
    std::shared_ptr<AudioServer> audioServer = std::make_shared<AudioServer>(systemAbilityId, true);
    const std::string deviceId = "";
    audioServer->OnAddSystemAbility(LAST_SYS_ABILITY_ID, deviceId);
}
} // namespace AudioStandard
} //