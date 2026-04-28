# Architecture

## 1. 项目定位

本项目是面向 CISO Assistant 的合规证据自动化处理工具，目标是减少审核项目中重复性的证据整理工作，包括多格式证据解析、初步分类、证据导入/复用、控制项挂接和 Observation 摘要生成。

项目默认不自动替代人工审核结论。AI 结果定位为“初筛建议 + 人工复核辅助”。

## 2. 总体架构

```text
Evidence Folder
PDF / DOCX / DOC / XLS / XLSX / CSV
        ↓
Document Parser
text extraction / table extraction / PDF extraction / metadata
        ↓
RawEvidence
file_name / sha256 / extracted_text / metadata
        ↓
ClassifierAgent
evidence-to-control relevance matching
        ↓
Candidate Filtering
ATTACH_MIN_SCORE + FINAL_TARGET_TOP_K + child requirement expansion
        ↓
CisoApiClient
create/reuse evidence + upload file + attach to requirement assessment
        ↓
AdviceAgent
control-level Observation summary + review suggestions
        ↓
CISO Assistant
evidence mapping + Observation + human review
```

## 3. 模块说明

### 3.1 Document Parser

负责将不同格式的证据文件解析为统一文本。

支持能力：

- PDF 文本抽取；
- DOCX / DOC 文档解析；
- XLS / XLSX 表格解析；
- TXT / MD / CSV 等文本文件读取；
- 文件 metadata、sha256、文件名等结构化信息封装。

### 3.2 RawEvidence

统一证据对象，作为解析层、分类层和导入层之间的中间结构。

典型字段：

- file_name；
- file_path；
- extension；
- sha256；
- extracted_text；
- metadata。

### 3.3 ClassifierAgent

负责根据证据内容和控制项信息计算相关度，输出候选控制项。

输入：

- 证据文件名；
- 解析后的正文文本；
- requirement catalog；
- 控制项标题、描述、实施等级。

输出：

- 候选 requirement assessment；
- 匹配分数；
- 匹配原因。

### 3.4 Candidate Filtering

候选控制项过滤层用于降低误挂风险。

关键配置：

```env
ATTACH_MIN_SCORE=0.40
FINAL_TARGET_TOP_K=10
```

含义：

- 低于最低相关度阈值的候选不自动挂接；
- 每份证据最多保留 Top-K 个候选控制项；
- 不限制一个控制项可以拥有多少份证据。

### 3.5 CisoApiClient

负责与 CISO Assistant 后端交互。

主要动作：

- 解析 assessment；
- 获取 requirement assessment；
- 创建或复用 evidence；
- 上传证据文件；
- 挂接 evidence 到控制项；
- 写入 Observation；
- 可选更新审核状态/结果。

### 3.6 AdviceAgent

负责将多份证据对同一控制项的支撑情况汇总为控制项级摘要。

输出内容包括：

- 主证据；
- 辅助证据；
- 待人工确认证据；
- 缺口摘要；
- 建议补充材料；
- AI 初审建议。

## 4. 安全边界

合规审核场景的误判成本较高，因此项目默认关闭自动回写最终审核结论。

推荐配置：

```env
AUTO_APPLY_REVIEW_DECISION=0
CISO_SCORE_WRITE_MODE=none
```

这意味着：

- AI 可以生成建议；
- AI 不直接修改合规状态；
- AI 不直接写入成熟度分数；
- 最终审核结论由人工确认。

## 5. 设计原则

1. 可追溯：输出 manifest，保留每份证据的分类和挂接计划。
2. 可回滚：默认 dry-run，不直接写系统。
3. 可控：通过阈值和 Top-K 控制挂接范围。
4. 人工兜底：AI 建议只作为辅助，不替代最终审计结论。
