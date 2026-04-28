# Demo Guide

## 1. Demo 目标

本 Demo 展示如何使用本项目完成合规证据的自动解析、初步分类、导入计划生成，以及可选的 CISO Assistant 证据挂接。

本项目默认以 dry-run 方式运行，不会修改真实 CISO Assistant 数据。

## 2. 准备环境

```bash
pip install -r requirements.txt
cp .env.example .env
```

Windows PowerShell 可以使用：

```powershell
Copy-Item .env.example .env
```

编辑 `.env`：

```env
CISO_BASE_URL=https://localhost:8443
CISO_USERNAME=your_username
CISO_PASSWORD=your_password
ASSESSMENT_ID=your_assessment_id
EVIDENCE_INPUT_DIR=demo_data/input
APPLY_IMPORT=0
AUTO_APPLY_REVIEW_DECISION=0
CISO_SCORE_WRITE_MODE=none
ATTACH_MIN_SCORE=0.40
FINAL_TARGET_TOP_K=10
```

## 3. 运行 dry-run

```bash
python -m tools.review_and_import
```

或者 PowerShell：

```powershell
$env:EVIDENCE_INPUT_DIR="demo_data/input"
$env:APPLY_IMPORT="0"
$env:AUTO_APPLY_REVIEW_DECISION="0"
$env:CISO_SCORE_WRITE_MODE="none"
$env:FINAL_TARGET_TOP_K="10"
python -m tools.review_and_import
```

## 4. 查看输出

运行后重点查看：

```text
import_review_manifest.json
review_decision_manifest.json
```

其中：

- `import_review_manifest.json`：每份证据的解析、分类、候选控制项和导入计划；
- `review_decision_manifest.json`：控制项级 AI 初审建议。

## 5. 正式导入前检查

正式导入前建议检查：

1. 候选控制项是否明显相关；
2. 是否有一份证据挂接过多控制项；
3. 低相关文件是否被跳过；
4. Observation 摘要是否可读；
5. 是否关闭自动回写最终结论。

推荐安全配置：

```env
APPLY_IMPORT=1
AUTO_APPLY_REVIEW_DECISION=0
CISO_SCORE_WRITE_MODE=none
```

## 6. 演示话术

可以这样介绍：

> 本项目不是直接让 AI 替代审核员，而是把证据解析、初步分类、导入挂接和 Observation 摘要自动化。考虑到合规审核误判成本较高，系统默认不自动回写最终合规结论，只输出候选控制项、匹配分数和人工复核建议。

## 7. 典型演示 Case

### Case 1：员工手册

期望匹配：

- 员工安全意识培训；
- 员工信息安全承诺；
- 员工制度知悉。

### Case 2：资产分类制度

期望匹配：

- 信息资产识别；
- 信息资产分类分级；
- 资产责任人和周期复核。

### Case 3：日志复核记录

期望匹配：

- 日志记录；
- 日志分析；
- 账号和访问复核。

### Case 4：事件报告

期望匹配：

- 事件处理；
- 事件记录；
- 整改和关闭确认。

## 8. 常见问题

### Q1：为什么不自动判定合规？

合规审核场景误判成本较高，所以默认只生成建议，不自动替代人工最终结论。

### Q2：为什么有些制度文件会匹配多个控制项？

制度类文件通常覆盖范围较广，因此可能命中多个控制项。项目通过 `ATTACH_MIN_SCORE` 和 `FINAL_TARGET_TOP_K` 控制挂接范围。

### Q3：为什么部分文件会被跳过？

常见原因包括：内容为空、无法解析、相关度低于阈值、格式暂未深度支持。
