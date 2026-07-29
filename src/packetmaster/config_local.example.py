"""复制为 config_local.py 后填写本机 API 配置；该文件不会提交到 Git。"""

# 诊断 Agent 使用的兼容 OpenAI API。MODEL_API_KEY 可使用环境变量临时覆盖。
MODEL_API_KEY = "replace-with-your-api-key"
MODEL_BASE_URL = "https://api.deepseek.com"
MODEL_NAME = "deepseek-v4-flash"
MODEL_STRUCTURED_OUTPUT_METHOD = "auto"

# RAG 默认使用 DashScope qwen3-vl-embedding；不要将真实 Key 写入 README 或提交到 Git。
# 也可改用环境变量 EMBEDDING_API_KEY，环境变量优先级高于此处默认值。
EMBEDDING_API_KEY = "replace-with-your-dashscope-api-key"
