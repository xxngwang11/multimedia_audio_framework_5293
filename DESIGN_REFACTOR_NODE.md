# Audio Suite 模块重构设计文档

## 1. 重构目标

简化 audio_suite 模块的设计，移除冗余的 Port 概念，使架构更加清晰简洁：

- 删除 `InputPort` 和 `OutputPort` 类
- 在 `AudioNode` 中直接使用 `preNodes_` 和 `nextNodes_` 维护节点连接关系
- 格式转换逻辑通过独立的 `AudioSuiteFormatConversion` 工具类处理

## 2. 当前设计的问题

### 2.1 Port 抽象价值不足

每个节点只有**一个**输入端口和一个输出端口，Port 并没有提供真正的多端口抽象能力。

### 2.2 职责模糊

- `InputPort` 和 `OutputPort` 只是简单地包装了连接关系和数据传递
- 没有独立的身份、配置或生命周期
- 端口类型（`AudioNodePortType`）几乎未被使用

### 2.3 相互依赖导致复杂度增加

```
InputPort 持有 unordered_map<OutputPort*, shared_ptr<AudioNode>>
OutputPort 持有 set<InputPort*>
```

连接/断开节点时需要同时更新两个对象，增加了维护成本。

### 2.4 代码冗余

Port 相关代码约 200 行，但并未解决任何实际问题。

## 3. 简化后的设计

### 3.1 核心变化

```
旧设计: Node → Port → Node
新设计: Node → Node
```

### 3.2 AudioNode 类结构

```cpp
class AudioNode : public std::enable_shared_from_this<AudioNode> {
public:
    AudioNode(AudioNodeType nodeType);
    AudioNode(AudioNodeType nodeType, AudioFormat audioFormat);
    virtual ~AudioNode() = default;

    virtual int32_t Init();
    virtual int32_t DeInit();
    virtual int32_t DoProcess(uint32_t needDataLength) = 0;
    virtual int32_t Flush() = 0;

    // 连接管理
    virtual int32_t Connect(const std::shared_ptr<AudioNode> &nextNode) = 0;
    virtual int32_t DisConnect(const std::shared_ptr<AudioNode> &preNode) = 0;

    // 数据获取
    virtual std::vector<AudioSuitePcmBuffer*> ReadPreNodeData(
        PcmBufferFormat outFormat, bool needConvert, uint32_t needDataLength);

    // 节点属性
    virtual AudioNodeInfo& GetAudioNodeInfo();
    virtual void SetAudioNodeId(uint32_t nodeId);
    virtual void SetAudioNodeFormat(AudioFormat audioFormat);
    virtual void SetAudioNodeVolume(float volume);
    virtual void SetAudioNodeDataFinishedFlag(bool finishedFlag);
    virtual AudioFormat GetAudioNodeFormat();
    virtual uint32_t GetAudioNodeId();
    virtual float GetAudioNodeVolume();
    virtual AudioNodeType GetNodeType();

protected:
    // 连接关系管理
    void AddNextNode(const std::shared_ptr<AudioNode>& node);
    void RemoveNextNode(const std::shared_ptr<AudioNode>& node);
    void AddPreNode(const std::shared_ptr<AudioNode>& node);
    void RemovePreNode(const std::shared_ptr<AudioNode>& node);

    // 输出数据管理
    int32_t WriteOutputData(AudioSuitePcmBuffer* data);
    std::vector<AudioSuitePcmBuffer*> PullOutputData(
        PcmBufferFormat outFormat, bool needConvert, uint32_t needDataLength);

    // 格式转换器初始化（子类根据需要重写）
    virtual int32_t InitFormatConverters();

protected:
    // 连接关系
    std::vector<std::weak_ptr<AudioNode>> preNodes_;
    std::vector<std::weak_ptr<AudioNode>> nextNodes_;

    // 输出数据缓冲
    std::vector<AudioSuitePcmBuffer*> outputData_;

    // 格式转换器（独立工具类，按需创建）
    std::vector<std::unique_ptr<AudioSuiteFormatConversion>> formatConverters_;

    // 临时数据（用于格式转换）
    std::vector<AudioSuitePcmBuffer> tmpData_;

private:
    AudioNodeInfo audioNodeInfo_;
    static uint32_t GenerateAudioNodeId();
    inline static std::mutex nodeIdCounterMutex_;
    inline static uint32_t nodeIdCounter_ = MIN_START_NODE_ID;
};
```

### 3.3 边界节点设计

| 节点类型 | preNodes_ | nextNodes_ |
|-----------|-----------|------------|
| AudioInputNode | 空（无上游） | 存储下游节点 |
| AudioOutputNode | 存储上游节点 | 空（无下游） |
| AudioSuiteProcessNode | 存储上游节点 | 存储下游节点 |

### 3.4 删除的类和枚举

```cpp
// 删除以下类
class InputPort<T>;
class OutputPort<T>;

// 删除以下枚举（无实际使用）
enum class AudioNodePortType {
    AUDIO_NODE_DEFAULT_OUTPORT_TYPE,
    AUDIO_NODE_HUMAN_SOUND_OUTPORT_TYPE,    // 未使用
    AUDIO_NODE_BACKGROUND_SOUND_OUTPORT_TYPE  // 未使用
};
```

## 4. API 设计

### 4.1 连接节点

```cpp
// 连接节点 A → B
int32_t AudioNode::Connect(const std::shared_ptr<AudioNode>& nextNode) {
    if (!nextNode) {
        return ERR_INVALID_PARAM;
    }
    // 当前节点添加下游
    AddNextNode(nextNode);
    // 下游节点添加上游
    nextNode->AddPreNode(shared_from_this());
    return SUCCESS;
}

// 断开连接
int32_t AudioNode::DisConnect(const std::shared_ptr<AudioNode>& preNode) {
    if (!preNode) {
        return ERR_INVALID_PARAM;
    }
    // 从当前节点移除上游
    RemovePreNode(preNode);
    // 从上游节点移除下游
    preNode->RemoveNextNode(shared_from_this());
    return SUCCESS;
}
```

### 4.2 数据流向

```cpp
// 下游节点获取上游数据
std::vector<AudioSuitePcmBuffer*> AudioNode::ReadPreNodeData(
    PcmBufferFormat outFormat, bool needConvert, uint32_t needDataLength)
{
    std::vector<AudioSuitePcmBuffer*> result;
    for (auto& weakNode : preNodes_) {
        if (auto node = weakNode.lock()) {
            auto data = node->PullOutputData(outFormat, needConvert, needDataLength);
            result.insert(result.end(), data.begin(), data.end());
        }
    }
    return result;
}

// 上游节点提供数据（触发处理+格式转换）
std::vector<AudioSuitePcmBuffer*> AudioNode::PullOutputData(
    PcmBufferFormat outFormat, bool needConvert, uint32_t needDataLength)
{
    // 触发节点处理
    DoProcess(needDataLength);

    if (outputData_.empty()) {
        return {};
    }

    std::vector<AudioSuitePcmBuffer*> outData;
    for (size_t idx = 0; idx < outputData_.size(); idx++) {
        AudioSuitePcmBuffer* data = outputData_[idx];
        CHECK_AND_RETURN_RET_LOG(data != nullptr, {}, "outputData is nullptr.");

        // 格式转换
        if (!needConvert || data->IsSameFormat(outFormat)) {
            outData.push_back(data);
        } else {
            CHECK_AND_RETURN_RET_LOG(formatConverters_[idx] != nullptr, {}, "converter is nullptr.");
            AudioSuitePcmBuffer* convertData = formatConverters_[idx]->Process(data, outFormat);
            CHECK_AND_RETURN_RET_LOG(convertData != nullptr, {}, "convertData is nullptr.");
            convertData->SetIsFinished(data->GetIsFinished());
            outData.push_back(convertData);
        }
    }

    outputData_.clear();
    return outData;
}

// 节点处理后写入输出数据
int32_t AudioNode::WriteOutputData(AudioSuitePcmBuffer* data) {
    outputData_.push_back(data);
    return SUCCESS;
}
```

### 4.3 格式转换器初始化

```cpp
int32_t AudioSuiteProcessNode::Init() {
    // ... 其他初始化逻辑 ...

    // 在 Init 中初始化格式转换器
    return InitFormatConverters();
}

int32_t AudioSuiteProcessNode::InitFormatConverters() {
    formatConverters_.clear();
    formatConverters_.emplace_back(std::make_unique<AudioSuiteFormatConversion>());
    tmpData_.resize(1);

    // 人声分离节点需要额外的转换器
    if (GetNodeType() == NODE_TYPE_AUDIO_SEPARATION) {
        formatConverters_.emplace_back(std::make_unique<AudioSuiteFormatConversion>());
        tmpData_.resize(2);
    }

    return SUCCESS;
}
```

## 5. 类结构变化

### 5.1 文件变更

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 删除 | `services/audio_suite/client/node/include/audio_suite_channel.h` | Port 类定义 |
| 删除 | `services/audio_suite/client/node/src/audio_suite_channel.cpp` | Port 类实现 |
| 修改 | `services/audio_suite/client/node/include/audio_suite_node.h` | 添加连接管理和数据获取接口 |
| 修改 | `services/audio_suite/client/node/src/audio_suite_node.cpp` | 实现新增接口 |
| 修改 | `services/audio_suite/client/node/include/audio_suite_process_node.h` | 移除 Port 成员，添加格式转换器 |
| 修改 | `services/audio_suite/client/node/src/audio_suite_process_node.cpp` | 适配新的数据流 API |
| 修改 | `services/audio_suite/client/node/include/audio_suite_input_node.h` | 移除 Port 成员 |
| 修改 | `services/audio_suite/client/node/src/audio_suite_input_node.cpp` | 适配新的数据流 API |
| 修改 | `services/audio_suite/client/node/include/audio_suite_output_node.h` | 移除 Port 成员 |
| 修改 | `services/audio_suite/client/node/src/audio_suite_output_node.cpp` | 适配新的数据流 API |
| 修改 | `services/audio_suite/client/node/include/audio_suite_mixer_node.h` | 移除 Port 成员 |
| 修改 | `services/audio_suite/client/node/src/audio_suite_mixer_node.cpp` | 适配新的数据流 API |

### 5.2 AudioSuiteProcessNode 变化

```cpp
// 旧设计
protected:
    OutputPort<AudioSuitePcmBuffer *> outputStream_;
    InputPort<AudioSuitePcmBuffer *> inputStream_;

// 新设计
protected:
    std::vector<std::unique_ptr<AudioSuiteFormatConversion>> formatConverters_;
    std::vector<AudioSuitePcmBuffer> tmpData_;

    // 继承自 AudioNode 的 preNodes_ 和 nextNodes_
    // 继承自 AudioNode 的 outputData_
```

## 6. 数据流向

### 6.1 处理流程

```
下游节点请求数据
    ↓
下游节点调用 ReadPreNodeData()
    ↓
遍历 preNodes_，调用每个节点的 PullOutputData()
    ↓
上游节点调用 DoProcess(needDataLength)
    ↓
上游节点调用 WriteOutputData() 将结果写入 outputData_
    ↓
PullOutputData() 返回数据（可选格式转换）
```

### 6.2 混音节点数据流

```
Mixer Node
    │
    ├── preNode A → PullOutputData() ──→ 数据A
    │
    ├── preNode B → PullOutputData() ──→ 数据B
    │
    └── SignalProcess({A, B}) → 混音处理 → WriteOutputData()
```

## 7. 迁移计划

### 7.1 阶段一：删除 Port 类

1. 删除 `audio_suite_channel.h` 和 `audio_suite_channel.cpp`

### 7.2 阶段二：修改 AudioNode 基类

1. 添加 `preNodes_` 和 `nextNodes_` 成员
2. 添加连接管理方法：`AddNextNode`, `RemoveNextNode`, `AddPreNode`, `RemovePreNode`
3. 添加数据获取方法：`ReadPreNodeData`, `PullOutputData`, `WriteOutputData`
4. 添加格式转换器成员：`formatConverters_`, `tmpData_`
5. 添加 `InitFormatConverters()` 虚函数

### 7.3 阶段三：修改 ProcessNode

1. 移除 `outputStream_` 和 `inputStream_`
2. 添加 `InitFormatConverters()` 实现
3. 修改 `ReadProcessNodePreOutputData()` 为调用 `ReadPreNodeData()`
4. 修改 `ProcessDirectly()`, `ProcessWithCache()`, `ProcessBypassMode()` 中的输出写入逻辑
5. 修改 `Connect()` 和 `DisConnect()` 直接管理节点连接

### 7.4 阶段四：修改 InputNode

1. 移除 `outputStream_`
2. 修改 `DoProcess()` 输出时调用 `WriteOutputData()`
3. 修改 `GetOutputPort()` 方法（移除或适配）

### 7.5 阶段五：修改 OutputNode

1. 移除 `inputStream_`
2. 修改 `DoProcess()` 调用 `ReadPreNodeData()` 获取数据
3. 适配 `Connect()` 和 `DisConnect()`

### 7.6 阶段六：修改 MixerNode

1. 确保 `ReadPreNodeData()` 正确处理多上游节点

### 7.7 阶段七：处理其他 ProcessNode 子类

检查并修改：
- `AudioSuiteEqNode`
- `AudioSuiteNrNode`
- `AudioSuiteSoundfieldNode`
- `AudioSuiteVoiceBeautifierNode`
- 等等...

### 7.8 阶段八：清理和测试

1. 删除相关测试文件中的 Port 测试代码
2. 更新 `AudioNodePortType` 相关代码
3. 编译检查
4. 运行单元测试

## 8. 风险评估

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 格式转换逻辑遗漏 | 部分节点无法正确转换格式 | 仔细迁移 `OutputPort::PullOutputData()` 中的转换逻辑 |
| 人声分离节点特殊处理 | 双输出逻辑可能出错 | 单独检查并测试 `NODE_TYPE_AUDIO_SEPARATION` 节点 |
| 循环引用问题 | weak_ptr 使用不当导致崩溃 | 确保所有连接使用 `weak_ptr` |
| 测试覆盖不足 | 遗漏边界情况 | 重点测试 Input/Output 节点和 Mixer 节点 |
