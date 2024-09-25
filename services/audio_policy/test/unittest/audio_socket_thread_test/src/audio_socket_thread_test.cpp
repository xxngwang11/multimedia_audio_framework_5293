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

#include "audio_socket_thread_test.h"
#include "audio_log.h"
#include "audio_errors.h"
#include "audio_pnp_server.h"
#include <thread>
#include <string>
#include <memory>
#include <vector>
#include <sys/socket.h>
#include <cerrno>
using namespace std;
using namespace std::chrono;
using namespace testing::ext;

namespace OHOS {
namespace AudioStandard {

AudioDevBusUsbDevice g_audioUsbDeviceList[AUDIO_UEVENT_USB_DEVICE_COUNT] = {};

void AudioSocketThreadUnitTest::SetUpTestCase(void) {}
void AudioSocketThreadUnitTest::TearDownTestCase(void) {}
void AudioSocketThreadUnitTest::SetUp(void) {}
void AudioSocketThreadUnitTest::TearDown(void) {}


#define PRINT_LINE printf("debug __LINE__:%d\n", __LINE__)

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_001
* @tc.desc  : Test IsUpdatePnpDeviceState.
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_001, TestSize.Level1)
{
    AudioEvent event1;
    event1.eventType = 1;
    event1.deviceType = 2;
    event1.name = "Device1";
    event1.address = "Address1";
    event1.anahsName = "AnahsName1";

    audioSocketThread_.UpdatePnpDeviceState(&event1);

    //Test the exact same event
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event1), false);

    //Test events with different eventtypes
    AudioEvent event2;
    event2.eventType = 2;  // change eventType
    event2.deviceType = 2;
    event2.name = "Device1";
    event2.address = "Address1";
    event2.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event2), true);

    //Test for events with different deviceTypes
    AudioEvent event3;
    event3.eventType = 1;
    event3.deviceType = 1;
    event3.name = "Device1";
    event3.address = "Address1";
    event3.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event3), true);

    //Test events with different names
    AudioEvent event4;
    event4.eventType = 1;
    event4.deviceType = 1;
    event4.name = "Device2";
    event4.address = "Address1";
    event4.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event4), true);

    // Test events with different addresses
    AudioEvent event5;
    event5.eventType = 1;
    event5.deviceType = 1;
    event5.name = "Device1";
    event5.address = "Address2";
    event5.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event5), true);

    //Test the anahsName for different events
    AudioEvent event6;
    event6.eventType = 1;
    event6.deviceType = 1;
    event6.name = "Device1";
    event6.address = "Address1";
    event6.anahsName = "AnahsName2";

    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event6), true);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_002
* @tc.desc  : Test IsUpdatePnpDeviceState.
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_002, TestSize.Level1)
{
    AudioEvent event1;
    event1.eventType = 1;
    event1.deviceType = 1;
    event1.name = "Device1";
    event1.address = "Address1";
    event1.anahsName = "AnahsName1";

    //Set the start state
    audioSocketThread_.UpdatePnpDeviceState(&event1);

    //Test completely different events
    AudioEvent event2;
    event2.eventType = 2;
    event2.deviceType = 2;
    event2.name = "Device2";
    event2.address = "Address2";
    event2.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event2), true);

    //Test events where both eventType and eventType are different
    AudioEvent event3;
    event3.eventType = 2;
    event3.deviceType = 2;
    event3.name = "Device1";
    event3.address = "Address1";
    event3.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event3), true);

    //Test for events where deviceType and name are different
    AudioEvent event4;
    event4.eventType = 1;
    event4.deviceType = 2;
    event4.name = "Device2";
    event4.address = "Address1";
    event4.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event4), true);

    //Test for events where both name and adress are different
    AudioEvent event5;
    event5.eventType = 1;
    event5.deviceType = 1;
    event5.name = "Device2";
    event5.address = "Address2";
    event5.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event5), true);

    //Test for events where both adress and anahsName are different
    AudioEvent event6;
    event6.eventType = 1;
    event6.deviceType = 1;
    event6.name = "Device1";
    event6.address = "Address2";
    event6.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event6), true);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_003
* @tc.desc  : Test IsUpdatePnpDeviceState.
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_003, TestSize.Level1)
{
    AudioEvent event1;
    event1.eventType = 1;
    event1.deviceType = 1;
    event1.name = "Device1";
    event1.address = "Address1";
    event1.anahsName = "AnahsName1";

    audioSocketThread_.UpdatePnpDeviceState(&event1);

    //Test events with different eventType, eventType, and name
    AudioEvent event2;
    event2.eventType = 2;
    event2.eventType = 2;
    event2.name = "Device2";
    event2.address = "Address1";
    event2.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event2), true);

    //Test events with different eventType, name, and address
    AudioEvent event3;
    event3.eventType = 2;
    event3.eventType = 2;
    event3.name = "Device2";
    event3.address = "Address1";
    event3.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event3), true);

    //Test for events where name, address, and anahsName are different
    AudioEvent event4;
    event4.eventType = 2;
    event4.eventType = 2;
    event4.name = "Device2";
    event4.address = "Address1";
    event4.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event4), true);

    // Test foraddress,anahsName and eventType are different
    AudioEvent event5;
    event5.eventType = 2;
    event5.eventType = 1;
    event5.name = "Device1";
    event5.address = "Address2";
    event5.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event5), true);

    //Test for events where address, anahsName, and eventType are different
    AudioEvent event6;
    event6.eventType = 2;
    event6.eventType = 2;
    event6.name = "Device1";
    event6.address = "Address1";
    event6.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event6), true);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_004
* @tc.desc  : Test IsUpdatePnpDeviceState.
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_004, TestSize.Level1)
{
    AudioEvent event1;
    event1.eventType = 1;
    event1.deviceType = 1;
    event1.name = "Device1";
    event1.address = "Address1";
    event1.anahsName = "AnahsName1";

    audioSocketThread_.UpdatePnpDeviceState(&event1);

    //Test events that are different for eventType, eventType, name, and adress
    AudioEvent event2;
    event2.eventType = 2;
    event2.deviceType = 2;
    event2.name = "Device2";
    event2.address = "Address2";
    event2.anahsName = "AnahsName1";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event2), true);

    //Test events where eventType, name, adress, and anahsName are all different
    AudioEvent event3;
    event3.eventType = 1;
    event3.deviceType = 2;
    event3.name = "Device2";
    event3.address = "Address2";
    event3.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event3), true);

    //Test for events where name, adress, anahsName, and eventType are all different
    AudioEvent event4;
    event4.eventType = 2;
    event4.deviceType = 1;
    event4.name = "Device2";
    event4.address = "Address2";
    event4.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event4), true);

    //Test for events where adress, anahsName, eventType, and deviceType are all different
    AudioEvent event5;
    event5.eventType = 2;
    event5.deviceType = 2;
    event5.name = "Device1";
    event5.address = "Address2";
    event5.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event5), true);

    //Test for events where anahsName, eventType, deviceType, and name are all different
    AudioEvent event6;
    event6.eventType = 2;
    event6.deviceType = 2;
    event6.name = "Device2";
    event6.address = "Address1";
    event6.anahsName = "AnahsName2";
    EXPECT_EQ(audioSocketThread_.IsUpdatePnpDeviceState(&event6), true);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_005
* @tc.desc  : Test SetAudioPnpUevent REMOVE_AUDIO_DEVICE
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_005, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "remove",
        .name = "TestDevice",
        .state = "removed",
        .devType = "headset",
        .subSystem = "audio",
        .switchName = "h2w",
        .switchState = "0",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_NE(result, SUCCESS);
    EXPECT_NE(event.eventType, PNP_EVENT_DEVICE_REMOVE);
    EXPECT_NE(event.deviceType, PNP_DEVICE_HEADSET);
    EXPECT_NE(event.name, "TestDevice");
    EXPECT_NE(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_006
* @tc.desc  : Test SetAudioPnpUevent ADD_DEVICE_HEADSET
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_006, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "add",
        .name = "TestDevice",
        .state = "added",
        .devType = "headset",
        .subSystem = "switch",
        .switchName = "h2w",
        .switchState = "1",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(event.eventType, PNP_EVENT_DEVICE_ADD);
    EXPECT_EQ(event.deviceType, PNP_DEVICE_HEADSET);
    EXPECT_EQ(event.name, "TestDevice");
    EXPECT_EQ(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_007
* @tc.desc  : Test SetAudioPnpUevent ADD_DEVICE_HEADSET_WITHOUT_MIC
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_007, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "add",
        .name = "TestDevice",
        .state = "added",
        .devType = "headset_without_mic",
        .subSystem = "switch",
        .switchName = "h2w",
        .switchState = "2",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(event.eventType, PNP_EVENT_DEVICE_ADD);
    EXPECT_EQ(event.deviceType, PNP_DEVICE_HEADSET);
    EXPECT_EQ(event.name, "TestDevice");
    EXPECT_EQ(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_008
* @tc.desc  : Test SetAudioPnpUevent_ADD_DEVICE_ADAPTER
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_008, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "add",
        .name = "TestDevice",
        .state = "added",
        .devType = "adapter",
        .subSystem = "switch",
        .switchName = "h2w",
        .switchState = "4",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(event.eventType, PNP_EVENT_DEVICE_ADD);
    EXPECT_EQ(event.deviceType, PNP_DEVICE_ADAPTER_DEVICE);
    EXPECT_EQ(event.name, "TestDevice");
    EXPECT_EQ(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_009
* @tc.desc  : Test SetAudioPnpUevent_ADD_DEVICE_MIC_BLOCKED
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_009, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "block",
        .name = "TestDevice",
        .state = "blocked",
        .devType = "mic",
        .subSystem = "switch",
        .switchName = "h2w",
        .switchState = "5",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(event.eventType, PNP_EVENT_MIC_BLOCKED);
    EXPECT_EQ(event.deviceType, PNP_DEVICE_MIC);
    EXPECT_EQ(event.name, "TestDevice");
    EXPECT_EQ(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_010
* @tc.desc  : Test SetAudioPnpUevent_ADD_DEVICE_MIC_UN_BLOCKED
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_010, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "unblock",
        .name = "TestDevice",
        .state = "unblocked",
        .devType = "mic",
        .subSystem = "switch",
        .switchName = "h2w",
        .switchState = "6",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(event.eventType, PNP_EVENT_MIC_UNBLOCKED);
    EXPECT_EQ(event.deviceType, PNP_DEVICE_MIC);
    EXPECT_EQ(event.name, "TestDevice");
    EXPECT_EQ(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_011
* @tc.desc  : Test SetAudioPnpUevent_UnknownState
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_011, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "unknown",
        .name = "TestDevice",
        .state = "unknown",
        .devType = "unknown",
        .subSystem = "switch",
        .switchName = "h2w",
        .switchState = "X", // 'X' UnknownState
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(event.eventType, PNP_EVENT_DEVICE_ADD);
    EXPECT_EQ(event.deviceType, PNP_DEVICE_UNKNOWN);
    EXPECT_EQ(event.name, "TestDevice");
    EXPECT_EQ(event.address, "TestDevName");
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_012
* @tc.desc  : Test SetAudioPnpUevent_NonSwitchSubsystem
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_012, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "change",
        .name = "headset",
        .state = "analog_hs0",
        .devType = "extcon",
        .subSystem = "other",
        .switchName = "h2w",
        .switchState = "0",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_EQ(result, ERROR);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_013
* @tc.desc  : Test SetAudioPnpUevent_InvalidSwitchName
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_013, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "remove",
        .name = "TestDevice",
        .state = "removed",
        .devType = "headset",
        .subSystem = "switch",
        .switchName = "invalid",
        .switchState = "0",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_EQ(result, ERROR);
    }

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_014
* @tc.desc  : Test SetAudioPnpUevent_InvalidAction
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_014, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "invalid",
        .name = "headset",
        .state = "analog_hs0",
        .devType = "extcon",
        .subSystem = "other",
        .switchName = "h2w",
        .switchState = "0",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };

    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_EQ(result, ERROR);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_015
* @tc.desc  : Test SetAudioPnpUevent_InvalidDevType
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_015, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "change",
        .name = "headset",
        .state = "analog_hs0",
        .devType = "invalid",
        .subSystem = "other",
        .switchName = "h2w",
        .switchState = "0",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };
    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_EQ(result, ERROR);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_016
* @tc.desc  : Test SetAudioPnpUevent_InvalidState
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_016, TestSize.Level1)
{
    AudioPnpUevent uevent = {
        .action = "change",
        .name = "headset",
        .state = "invalid",
        .devType = "extcon",
        .subSystem = "other",
        .switchName = "h2w",
        .switchState = "0",
        .hidName = "hid",
        .devName = "TestDevName",
        .anahsName = "anahs"
    };
    AudioEvent event;
    int32_t result = AudioSocketThread::SetAudioPnpServerEventValue(&event, &uevent);
    EXPECT_EQ(result, ERROR);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_017
* @tc.desc  : Test FindAudioUsbDevice_FindEffectiveDevice
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_017, TestSize.Level1)
{
    const char *validDevName = "usb_device_1";
    g_audioUsbDeviceList[0].isUsed = true;
    bool result = AudioSocketThread::FindAudioUsbDevice(validDevName);
    EXPECT_FALSE(result);
}

/**
* @tc.name  : Test AudioSocketThread.
* @tc.number: AudioSocketThread_018
* @tc.desc  : Test FindAudioUsbDevice_FindInvalidDevice
*/
HWTEST_F(AudioSocketThreadUnitTest, AudioSocketThread_018, TestSize.Level1)
{
    const char *invalidDevName = "non_existent_device";
    bool result = AudioSocketThread::FindAudioUsbDevice(invalidDevName);
    EXPECT_FALSE(result);
}
} // namespace AudioStandard
} // namespace OHOS
