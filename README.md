# CISO Evidence Multi-Agent

基于 CrewAI、Ollama 与 CISO Assistant API 的安全合规证据自动处理原型。

## 实测结果

当前测试场景下，本项目已完成以下验证：

- 52 个测试证据文件批量处理
- 52 个文件流程完成
- 0 个导入失败
- 0 个流程失败
- 可输出单文件整改建议
- 可输出控制项级整改建议总报告
- 等保二级 / 三级测试目标验证
- 多批次测试证据自动分类导入
- 证据自动绑定至目标控制项

## 项目简介

本项目面向等保/合规审计场景，尝试将传统依赖人工完成的证据整理、分类、导入与初审流程进行自动化拆分与编排，形成一个可运行的多角色处理闭环。

系统围绕“证据读取 -> 有效性校验 -> 控制项分类 -> API 自动导入 -> AI 初审 -> 整改建议 -> 汇总报告”展开，目标是帮助审计人员在正式审核前完成预检查、补证建议生成和整改优先级分析，降低人工整理成本，提高证据处理效率。

## 项目目标

本项目主要解决以下问题：

- 审计证据种类多、人工整理成本高
- 证据与控制项之间的挂载依赖经验，标准不统一
- 导入 CISO Assistant 过程重复、效率低
- 单份证据难以快速判断是否充分支撑控制项
- 审计前缺少统一的补证建议和整改优先级输出

## 核心能力

- 多类型证据文件读取与最小有效性筛选
- 基于本地 Ollama 的 requirement / 控制项分类
- 通过 CISO Assistant API 自动创建或复用证据并绑定控制项
- 基于分类结果执行 AI 初审
- 为单份证据输出整改建议与提分预估
- 为整批证据输出控制项级整改建议总报告

## 技术栈

- Python
- CrewAI
- Ollama
- CISO Assistant API
- JSON / Markdown 报告输出

## 多角色设计

本项目采用多角色协同思路，将证据处理链路拆分为以下角色：

### 1. Validator Agent

负责证据最小有效性判断，主要识别：

- 文件是否可读取
- 内容是否为空
- 是否为明显无效或纯噪声文件

### 2. Classifier Agent

负责将证据与目标 assessment 下的 requirement / 控制项进行匹配，输出：

- 命中的控制项
- 控制项标题
- 匹配理由
- 置信度

### 3. Import Agent

负责通过 API 将证据导入到 CISO Assistant，并完成：

- evidence 创建或复用
- 文件上传
- requirement assessment 关联

### 4. PreAudit Agent

负责基于证据内容和已匹配控制项进行 AI 初审，输出：

- 合规 / 部分合规 / 不合规 / 存疑
- 主要问题
- 基础改进建议
- 当前估分区间
- 补证后预计提分区间

### 5. Aggregate Report Logic

负责汇总整批 `result.json`，生成控制项级总建议报告，输出：

- 各控制项涉及的证据
- 共性问题
- 缺失证据
- 建议补充文件
- 优先级建议
- 预计提分区间

## 处理流程

整体流程如下：

1. 从输入目录读取证据文件
2. 对证据做最小有效性筛选
3. 读取目标 assessment 的 requirement catalog
4. 使用本地 LLM 对证据进行控制项匹配
5. 调用 CISO Assistant API 自动导入证据并绑定 requirement
6. 执行 AI 初审，输出单文件整改建议
7. 汇总所有结果，生成批量整改建议总报告

## 项目结构

```text
ciso-evidence-multiagent/
├─ app/                # 入口与配置
├─ agents/             # 各类 agent 逻辑
├─ flows/              # 主处理流程编排
├─ schemas/            # 数据模型定义
├─ tools/              # API、解析、日志、汇总工具
├─ .env.example        # 配置模板
├─ .gitignore
├─ README.md
└─ requirements.txt
```

## 支持的证据类型

当前原型支持以下类型作为输入证据：

- PDF
- DOCX
- DOC
- MD
- TXT
- PNG / JPG / JPEG

## 环境配置

先复制 `.env.example` 为 `.env`，再按实际环境填写参数：

```env
CISO_BASE_URL=https://localhost:8443/api
CISO_API_TOKEN=your_token_here
CISO_VERIFY_SSL=false

OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=deepseek-r1:8b
OLLAMA_TIMEOUT=180

EVIDENCE_INPUT_DIR=D:\evidence_demo\input
EVIDENCE_OUTPUT_DIR=D:\evidence_demo\output
```

## 安装依赖

```bash
pip install -r requirements.txt
```

## 运行方式

### 1. 启动本地 Ollama

确保本地模型已可用，例如：

```bash
ollama list
```

### 2. 准备输入证据

将待处理证据放入输入目录，例如：

```text
D:\evidence_demo\input
```

### 3. 执行批处理

按 assessment 名称运行：

```bash
python -m app.main --assessment-name "test等保"
```

或按 assessment id 运行：

```bash
python -m app.main --assessment-id "your-assessment-id"
```

## 输出结果

运行后会在输出目录生成以下文件：

### 1. 单文件结果

`xxx.result.json`

包含：

- 原始证据信息
- 校验结果
- 分类结果
- 导入结果
- 初审结果
- gap_report / 提分建议

### 2. 单文件整改建议

`xxx.remediation.md`

用于展示：

- 当前结论
- 当前估分
- 缺失证据
- 建议补充文件
- 优先级动作
- 预计提分区间

### 3. 批量汇总结果

`_summary.json`

用于记录整批处理的基础状态。

### 4. 批量整改建议总报告

`_aggregate_remediation_report.md`

用于按控制项输出：

- 涉及证据
- 主要问题
- 建议动作
- 缺失证据
- 建议补充文件
- 优先级建议
- 预计提分区间

## 项目效果

在当前测试场景下，项目已具备以下能力：

- 证据自动读取与校验
- 控制项自动匹配
- 证据自动导入与控制项绑定
- 单文件整改建议输出
- 控制项级整改建议总报告输出

这说明该原型已经具备从“证据输入”到“控制项挂载”再到“整改建议输出”的基本闭环能力。

## 示例能力说明

以等保二级测试目标为例，系统可实现：

- 将批量测试证据自动导入目标 assessment
- 将证据自动关联到对应 requirement / 控制项
- 根据初审结果提示当前证据不足点
- 推荐补充哪些文件更有助于提分
- 生成整体整改优先级建议

例如，总报告能够针对各控制项自动给出：

- 当前证据成熟度
- 主要缺口
- 缺失证据类型
- 建议补充文件
- 优先整改顺序
- 预计提分区间

## 适用场景

本项目适用于以下场景：

- 等保 / 合规审计前的预检查
- 审计材料整理与补证辅助
- 证据与控制项的批量挂载
- 审计准备阶段的整改优先级分析
- 安全治理 / 合规平台化探索

## 当前局限

当前版本仍存在一些已知限制：

- 图片类证据依赖 OCR，稳定性低于文本类证据
- 某些控制项之间语义接近，可能出现多对多匹配偏差
- AI 初审中的“预计提分”属于估计区间，不能替代正式人工评分
- 不同框架下的控制项语义差异仍需要进一步增强约束
- 当前更适合用作“审计辅助工具”，而不是完全替代人工审核

## 后续优化方向

后续可进一步增强以下能力：

- 增强 OCR 与图片类证据识别能力
- 区分“主控制项归属”和“文中引用条款”
- 提升分类与初审的规则约束能力
- 支持更多框架，例如等保三级、ISO 27001、GDPR、PIPL
- 增加人工复核闭环与评分回写能力
- 增加前端展示页面，直接查看单文件建议与总报告


## 安全说明

本仓库为公开版本：

- 已移除真实 token、运行日志及敏感配置
- `.env` 不纳入版本控制
- 示例数据应使用脱敏材料
- 请勿上传真实客户证据与内部审计数据
