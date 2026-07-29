from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "ai-kubernetes-agent"
    debug: bool = False
    kubeconfig_path: str = "$HOME/.kube/config"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: int = 120
    ollama_json_format: bool = True

    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_database: str = "ai_kubernetes_agent"


settings = Settings()
