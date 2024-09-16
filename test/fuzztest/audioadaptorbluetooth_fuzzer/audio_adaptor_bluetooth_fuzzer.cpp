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

#include <iostream>
#include <cstddef>
#include <cstdint>
#include "audio_info.h"
#include "audio_policy_server.h"
#include "audio_policy_service.h"
#include "audio_bluetooth_manager.h"
#include "audio_hdiadapter_info.h"
#include "bluetooth_renderer_sink.h"
#include "audio_device_info.h"
#include "i_audio_renderer_sink.h"

namespace OHOS {
namespace AudioStandard {
using namespace std;
const int32_t LIMITSIZE = 4;
const char *SINK_ADAPTER_NAME = "primary";
const uint64_t COMMON_UINT64_NUM = 2;
const int64_t COMMON_INT64_NUM = 2;

IMmapAudioRendererSink *GetAdaptorBlueToothSink()
{
    return BluetoothRendererSink::GetMmapInstance();
}

void IsInitedFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->IsInited();
}

void SetVoiceVolumeFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }

    float volume = *reinterpret_cast<const float*>(rawData);
    GetAdaptorBlueToothSink()->SetVoiceVolume(volume);
}

void SetAudioSceneFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    AudioScene audioScene = *reinterpret_cast<const AudioScene *>(rawData);
    DeviceType deviceType = *reinterpret_cast<const DeviceType *>(rawData);
    std::vector<DeviceType> activeDevices = {deviceType};
    GetAdaptorBlueToothSink()->SetAudioScene(audioScene, activeDevices);
}

void SetOutputRoutesFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    DeviceType deviceType = *reinterpret_cast<const DeviceType *>(rawData);
    std::vector<DeviceType> outputDevices = {deviceType};
    GetAdaptorBlueToothSink()->SetOutputRoutes(outputDevices);
}

void SetAudioParameterFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    AudioParamKey key = *reinterpret_cast<const AudioParamKey *>(rawData);
    std::string condition = "123456";
    std::string value = "123456";
    GetAdaptorBlueToothSink()->SetAudioParameter(key, condition, value);
}

void GetAudioParameterFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    AudioParamKey key = *reinterpret_cast<const AudioParamKey *>(rawData);
    std::string condition = "123456";
    GetAdaptorBlueToothSink()->GetAudioParameter(key, condition);
}

void RegisterParameterCallbackFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    IAudioSinkCallback *callback_ = nullptr;
    GetAdaptorBlueToothSink()->RegisterParameterCallback(callback_);
}

void InitFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) { // 忽略内存对齐
        return;
    }
    IAudioSinkAttr attr = {};
    attr.adapterName = SINK_ADAPTER_NAME;
    attr.sampleRate = *reinterpret_cast<const uint32_t *>(rawData);
    attr.channel = *reinterpret_cast<const uint32_t *>(rawData);
    attr.format = *reinterpret_cast<const HdiAdapterFormat *>(rawData);
    attr.channelLayout = COMMON_UINT64_NUM;
    attr.deviceType = *reinterpret_cast<const DeviceType *>(rawData);
    attr.volume = *reinterpret_cast<const float *>(rawData);
    attr.openMicSpeaker = *reinterpret_cast<const uint32_t *>(rawData);
    GetAdaptorBlueToothSink()->Init(attr);
}

void RenderFrameFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    char data = *const_cast<char*>(reinterpret_cast<const char*>(rawData));
    uint64_t len = COMMON_UINT64_NUM;
    uint64_t writeLen = COMMON_UINT64_NUM;
    GetAdaptorBlueToothSink()->RenderFrame(data, len, writeLen);
}

void StartFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->Start();
}

void SetVolumeFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    float left = *reinterpret_cast<const float*>(rawData);
    float right = *reinterpret_cast<const float*>(rawData);
    GetAdaptorBlueToothSink()->SetVolume(left, right);
}

void GetVolumeFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    float left, right;
    if (size >= sizeof(left)) {
        left = *reinterpret_cast<const float*>(rawData);
    } else {
        return;
    }
    if (size >= sizeof(right)) {
        right = *reinterpret_cast<const float*>(rawData);
    } else {
        return;
    }
    GetAdaptorBlueToothSink()->GetVolume(left, right);
}

void GetTransactionIdFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    uint64_t transactionId = COMMON_UINT64_NUM;
    GetAdaptorBlueToothSink()->GetTransactionId(&transactionId);
}

void StopFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->Stop();
}

void PauseFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->Pause();
}

void ResumeFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->Resume();
}

void ResetFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->Reset();
}

void FlushFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->Flush();
}

void SuspendRenderSinkFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->SuspendRenderSink();
}

void RestoreRenderSinkFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetAdaptorBlueToothSink()->RestoreRenderSink();
}

void GetPresentationPositionFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    uint64_t frames = COMMON_UINT64_NUM;
    int64_t timeSec = COMMON_INT64_NUM;
    int64_t timeNanoSec = COMMON_INT64_NUM;
    GetAdaptorBlueToothSink()->GetPresentationPosition(frames, timeSec, timeNanoSec);
}

void ResetOutputRouteForDisconnectFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE || size < sizeof(DeviceType)) {
        return;
    }
    DeviceType deviceType = *reinterpret_cast<const DeviceType *>(rawData);
    GetAdaptorBlueToothSink()->ResetOutputRouteForDisconnect(deviceType);
}

void SetPaPowerFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    int32_t flag = *reinterpret_cast<const int32_t *>(rawData);
    GetAdaptorBlueToothSink()->SetPaPower(flag);
}
} // namespace AudioStandard
} // namesapce OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AudioStandard::InitFuzzTest(data, size);
    OHOS::AudioStandard::StartFuzzTest(data, size);
    OHOS::AudioStandard::IsInitedFuzzTest(data, size);
    OHOS::AudioStandard::SetVoiceVolumeFuzzTest(data, size);
    OHOS::AudioStandard::SetAudioSceneFuzzTest(data, size);
    OHOS::AudioStandard::SetOutputRoutesFuzzTest(data, size);
    OHOS::AudioStandard::SetAudioParameterFuzzTest(data, size);
    OHOS::AudioStandard::GetAudioParameterFuzzTest(data, size);
    OHOS::AudioStandard::RegisterParameterCallbackFuzzTest(data, size);
    OHOS::AudioStandard::SetVolumeFuzzTest(data, size);
    OHOS::AudioStandard::GetVolumeFuzzTest(data, size);
    OHOS::AudioStandard::GetTransactionIdFuzzTest(data, size);
    OHOS::AudioStandard::SuspendRenderSinkFuzzTest(data, size);
    OHOS::AudioStandard::RestoreRenderSinkFuzzTest(data, size);
    OHOS::AudioStandard::GetPresentationPositionFuzzTest(data, size);
    OHOS::AudioStandard::ResetOutputRouteForDisconnectFuzzTest(data, size);
    OHOS::AudioStandard::SetPaPowerFuzzTest(data, size);
    OHOS::AudioStandard::PauseFuzzTest(data, size);
    OHOS::AudioStandard::ResumeFuzzTest(data, size);
    OHOS::AudioStandard::ResetFuzzTest(data, size);
    OHOS::AudioStandard::FlushFuzzTest(data, size);
    OHOS::AudioStandard::StopFuzzTest(data, size);
    return 0;
}
