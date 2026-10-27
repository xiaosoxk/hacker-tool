.PHONY: setup test sandbox-build sandbox-up run approve replay clean

setup:            ## 安装依赖（建议先 python -m venv .venv）
	pip install -r requirements.txt && pip install -e .

test:             ## 离线全量测试（无网络、无 Docker）
	python -m pytest tests -v

sandbox-build:    ## 构建沙箱与编排镜像
	docker compose -f deploy/docker-compose.yml build

sandbox-up:       ## 启动隔离环境（agent + sandbox + 靶机）
	docker compose -f deploy/docker-compose.yml up -d

run:              ## 离线演示（FakeLLM）
	AEGIS_OFFLINE=1 python -m secagent.main run --task task.example.yaml --roe roe.example.yaml

approve:          ## 批准高危动作（沙箱内 POC 验证）
	AEGIS_OFFLINE=1 python -m secagent.main approve --thread T1

replay:           ## 回放审计日志
	python -m secagent.main replay --audit data/audit.log

clean:
	rm -rf data/ .pytest_cache **/__pycache__
