# ciso_multiagent_starter_v2

面向 CISO Assistant 的多 Agent 证据分类导入 MVP（Ollama 版）。

## 这版解决的问题

- 支持本地 **Ollama** 做 AI 分类
- 不再依赖静态规则库做最终分类
- 通过 `assessment_id` 或 `assessment_name + framework` 动态锁定目标审计
- 从 **目标审计** 动态拉取 requirement assessments，作为 AI 的候选控制项
- 支持 **多对多** 分类：一个证据可挂到多个 requirement assessment
- `name=test` 这种场景可用；若同名 assessment 存在于不同 framework，需额外传 framework 或直接传 assessment_id

## 推荐调用方式

### 最稳：直接传 assessment_id
```bash
python -m app.main --assessment-id <uuid>
```

### 按名称选择 assessment
```bash
python -m app.main --assessment-name test --assessment-framework "ISO/IEC - International standard ISO/IEC 27001:2022"
```

### 只做本地分类，不导入
```bash
python -m app.main
```

## 依赖
```bash
pip install -r requirements.txt
```

## Ollama
默认调用：
- `http://localhost:11434/api/chat`
- 模型默认：`qwen2.5:7b`

请先确保：
```bash
ollama list
ollama run qwen2.5:7b
```
