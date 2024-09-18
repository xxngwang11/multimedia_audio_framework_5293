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
#ifndef USERDATA_H
#define USERDATA_H

#include <pulsecore/core.h>
#include <pulsecore/log.h>
#include <pulsecore/module.h>
#include <pulsecore/source.h>
#include <pulsecore/thread-mq.h>
#include <pulsecore/thread.h>
#include <pulsecore/hashmap.h>

#include "audio_hdiadapter_info.h"
#include "hdi_adapter_manager_api.h"
#include "capturer_source_adapter.h"

#define DEFAULT_SCENCE_BYPASS "scene.bypass"
#define MAX_SCENE_NAME_LEN 100
#define SCENE_TYPE_OFFSET 16
#define CAPTURER_ID_OFFSET 8
#define BYTE_SIZE_SAMPLE_U8 1
#define BYTE_SIZE_SAMPLE_S16 2
#define BYTE_SIZE_SAMPLE_S24 3
#define BYTE_SIZE_SAMPLE_S32 4
#define BASE_TEN 10

struct Userdata{
    pa_core *core;
    pa_module *module;
    pa_source *source;
    pa_thread *thread;
    pa_thread_mq *thread_mq;
    pa_rtpoll *rtpoll;
    uint32_t bufferSize;
    uint32_t openMicSpeaker;
    pa_usec_t blockUsec;
    pa_usec_t timestamp;
    SourceAttr attrs;
    bool isCapturerStarted;
    EcType ecType;
    const char *ecAdapterName;
    uint32_t ecSamplingRate;
    int32_t ecFormat;
    unit32_t ecChannels;
    MicRefSwitch micRef;
    uint32_t micRefRate;
    int32_t micRefFormat
    unit32_t micRefChannels;
    pa_hashmap *sceneToResamplermap;
    uint32_t captureId;
    unit32_t renderId;
    HdiCaptureHandle *captureHandleEc;
    HdiCaptureHandle *captureHandleMicRef;
    unit64_t requestBytesEc;
    uint64_t requestBytesMicRef;
    void *bufferEc;
    void *bufferMicRef;
};

#endif //USERDATA_H