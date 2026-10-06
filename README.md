# 山火事件指挥与离线人员调度

维护火线、风向、资源和任务区，合并离线现场记录并防止人员重复分配。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8319
```

默认端口为`8319`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `POST /api/items/{id}/rollback`，回退补偿，必须提交`request_id`、`reason`、`expected_version`、`target_status`
- `GET /api/audit`

允许角色：field_commander, incident_commander, logistics, viewer。火线长度、风向变化和离线记录数量影响风险等级；同一资源不能同时出现在多个活动任务中。

## 回退补偿流程

误推状态（如`controlled`退回`active`）不直接改状态，而是带权责的补偿：

- 提交时写明误判依据`reason`、期望版本`expected_version`、目标状态`target_status`和请求编号`request_id`；无指挥角色（field_commander、incident_commander以外）按越权拒绝。
- 系统逐项核对关闭签认（`closure_signoff`）、未结事项（打开的`records`）和资源释放（`resource_release`），核对清单写入检查点与审计。
- 派生记录（关闭签认、资源释放）标记作废（`voided_at`/`voided_by`/`void_reason`），不删除；事件生成新版本，原流转与审计事件继续可查。
- 推进与回退并发时以版本号裁决，先落账的一方生效；后到者请求置为`failed`，拿新版本按原`request_id`重办。
- 写入失败从检查点恢复；按`request_id`重试，已完成的请求重放原结果，重复只算一次。
- 旧库自动迁移：没有版本号的旧记录迁移成首版（`version=1`），记录表补作废列。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
