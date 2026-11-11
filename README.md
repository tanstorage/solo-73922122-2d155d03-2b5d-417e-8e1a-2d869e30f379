# 共享文件服务器读取权限 · 离线诊断台 + TUF 根信任轮换

本仓库包含两个相互独立、共用同一 FastAPI 服务的能力：

1. **读取权限离线诊断**：在浏览器编辑运维采集的目录快照 JSON 与读取请求 JSON，
   由后端按 Linux 无特权进程规则完整模拟路径解析（namei）与 DAC / POSIX ACL 判定。
   全程只在内存中计算，不读取、不探测宿主机上的任何文件或路径。
2. **TUF 根信任轮换**：为长期断网的更新客户端补齐签名密钥轮换链。浏览器上传
   1～8 份按版本排列的 root 元数据（仅 Ed25519），按 **TUF 1.0.37** 规则做整链验签；
   整链通过才以 SQLite 原子替换受信 root，失败保留原根并指出版本与原因；
   可在网页查看并下载当前受信 root 供客户端安装。

容器以非 root、只读根文件系统、丢弃全部 Linux capability 的方式运行；
仅 `/data` 命名卷可写，用于保存 SQLite 数据库与跨进程锁文件。

## 一、启动

### 方式 A：Docker Compose（推荐，可实际演示）

```bash
docker compose up --build
# 浏览器打开
#   http://localhost:8000/        诊断台首页（含 TUF 入口）
#   http://localhost:8000/roots   TUF 根信任轮换页
```

服务以 **2 个 uvicorn 工作进程**运行；并发提交由 POSIX 文件锁 + SQLite 事务串行化，
后到的请求以锁内读到的最新受信 root 为验证起点，不会覆盖另一请求已提交的更新。
受信 root 保存在命名卷 `tuf-data` 的 SQLite 中，容器重启/重建后结果保留。

### 方式 B：本机 Python（3.11+）

```bash
python3 -m pip install -r requirements.txt   # 离线环境请提前准备 wheelhouse
./run.sh                                      # 默认 2 个工作进程，WORKERS=1 可调整
# 打开 http://localhost:8000/roots
```

本机运行时若 `/data` 不可写，数据库自动落到项目根的 `var/tuf.db`（已在 `.gitignore`）。

健康检查：`GET /health`；OpenAPI 文档：`GET /docs`。

## 二、TUF 根信任轮换（TUF 1.0.37，仅 Ed25519）

### 2.1 受信 root 的来源

* **仅首次启动**：SQLite 中不存在受信 root 时，从启动文件
  `app/bootstrap/trusted-root.v1.json` 载入引导 root（version=1），并写入审计表。
* **之后的重启**：数据库已有受信 root，启动文件不会再次生效；更新只能通过
  浏览器上传的轮换链完成。

### 2.2 验签规则（服务实现与页面提示一致）

1. **仅 Ed25519**：`keytype`/`scheme` 必须为 `ed25519`；
   `keyid = sha256(canonical JSON(key))`，与登记值不符即拒绝。
2. **canonical JSON**：按 TUF 1.0.37 的 OLPC canonical JSON 规则编码 `signed` 部分后验签。
3. **版本逐次加 1**：首份候选 root 的版本必须是受信版本 + 1，之后每份 = 上一份 + 1；
   重复版本、版本跳跃均拒绝（上传文件按内部 `signed.version` 自动排序）。
4. **双重阈值**：每份候选 root 必须同时满足
   ① 上一版 root 中 root 角色登记的密钥与阈值；
   ② 候选 root 自身 root 角色登记的密钥与阈值。
5. **重复 keyid 不凑数**：同一 keyid 的多条签名只计一次；未知 keyid、
   非 root 角色密钥的签名忽略；签名编码非法或验签不通过不计入有效签名。
6. **过期策略**：中间版本 root 允许已过期；**最终 root 的 `expires` 必须晚于
   本次更新开始时间**（请求进入时刻，UTC），恰好相等也不接受。
7. **原子性**：整链全部通过才替换 SQLite 中的受信 root；任一环节失败则
   原根原样保留，响应与审计记录给出失败版本号和原因。
8. **数量限制**：每次提交 1～8 份 root，单文件默认上限 1 MiB
   （`TUF_MAX_UPLOAD_BYTES` 可调）。

### 2.3 浏览器操作（`/roots`）

1. 面板①展示当前受信 root 的版本、`spec_version`、过期时间、root 阈值与 keyid，
   可一键**下载**（`trusted-root.v<N>.json`）交给断网客户端安装。
2. 面板②选择或拖入 1～8 份 root JSON，提交后展示每个版本的双重阈值验签明细
   （每条签名的通过/失败/忽略处置）与过期判定。
3. 面板③一键载入内置轮换示例；面板⑥展示含成功/失败/引导在内的审计记录。

### 2.4 内置轮换示例（固定种子，可重复生成）

```bash
python scripts/generate_demo_roots.py
```

| 文件 | 版本 | 说明 |
| --- | --- | --- |
| `app/bootstrap/trusted-root.v1.json` | 1 | 启动引导受信 root（K1/K2/K3，阈值 2） |
| `app/static/demo/root.v2.json` | 2 | 合法链：旧密钥集不变（中间根，允许过期） |
| `app/static/demo/root.v3.json` | 3 | 合法链：轮换到 K3/K4，K3 桥接新旧信任 |
| `app/static/demo/root.v4.json` | 4 | 合法链：加入 K5，最终根 2032 年到期 |
| `app/static/demo/root.bad-threshold.v4.json` | 4 | 失败示例：自身阈值 3 但角色仅 2 个 keyid |
| `app/static/demo/root.bad-expired.v4.json` | 4 | 失败示例：最终根已过期 |

页面“载入合法链 v2-v4”后直接提交即可看到 v1→v4 的成功轮换；
两个失败链分别演示阈值不足与最终根过期时的拒绝行为。

### 2.5 HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/roots` | TUF 根信任轮换页面 |
| GET  | `/api/root` | 当前受信 root 概要（版本/阈值/keyid/过期时间） |
| GET  | `/api/root/download` | 下载受信 root 原文（attachment） |
| POST | `/api/root/update` | multipart 上传 1～8 份 root，整链验证并替换 |
| GET  | `/api/root/audit?limit=20` | 审计记录（成功/失败/引导，重启保留） |

`POST /api/root/update` 失败响应示例：

```json
{
  "ok": false,
  "error_type": "chain_error",
  "failed_version": 4,
  "message": "最终 root 已过期或恰好到期：expires=2026-10-01T00:00:00+00:00 不晚于本次更新开始时间 2026-11-11T12:00:00+00:00"
}
```

### 2.6 并发与持久化

* 两个工作进程共享同一 SQLite（WAL 模式）与锁文件 `tuf.db.lock`；
  “读取最新受信 root → 整链验证 → 替换提交”整体在 `flock` 排他锁内完成，
  并在事务内二次校验版本，杜绝并发覆盖。
* 受信 root 单行存储（`trusted_root` 表），更新为单事务原子替换；
  所有尝试写入 `root_audit` 表，重启后完整保留。

## 三、读取权限离线诊断（原有能力）

### 快照 snapshot（最多 100 个节点）

```json
{
  "users":  {"1001": "alice"},
  "groups": {"1000": "staff"},
  "nodes": [
    {
      "path": "/srv/secret.txt",
      "type": "file",
      "uid": 0, "gid": 0,
      "mode": "640",
      "acl": [
        {"type": "user_obj",  "perms": "rw-"},
        {"type": "user",      "qualifier": 1001, "perms": "rwx"},
        {"type": "group_obj", "perms": "r--"},
        {"type": "group",     "qualifier": 1000, "perms": "r-x"},
        {"type": "mask",      "perms": "r--"},
        {"type": "other",     "perms": "---"}
      ]
    }
  ]
}
```

判定语义与 Linux 对齐：逐级 `--x` 搜索（EACCES 优先于 ENOENT）、软链接物理展开、
最多 40 次（ELOOP）、不做词法 `..` 折叠、ACL 命中即终局不退回 other 等，
详见页面与 `app/resolver.py` 注释。

## 四、测试

```bash
python3 -m pytest tests/ -q
```

覆盖（共 110+ 用例）：

* TUF：canonical JSON 编码、Ed25519 keyid/验签、非 Ed25519 拒绝、root 结构校验、
  版本逐次加 1、双重阈值、重复 keyid 不凑数、未知 keyid 忽略、坏签名不计、
  中间根过期允许/最终根过期拒绝、8 份上限；
* 存储：首次引导且仅一次、成功替换、失败保留原根、重复版本/版本跳跃、
  SQLite 重启持久化、多线程并发提交只成功一次且不覆盖；
* API：页面与静态资源、受信根信息/下载、multipart 上传、失败版本与原因、审计、
  后续请求以最新受信根为起点；
* 诊断：逐级 search、mode/ACL 各分支、mask、软链接、物理 `..`、40 次边界、
  错误定位与全部内置示例。

## 五、目录结构

```
app/
  main.py                 # FastAPI 路由（诊断 + TUF）
  engine.py / resolver.py # 诊断引擎与路径解析
  tuf/
    canonicaljson.py      # TUF canonical JSON
    keys.py               # Ed25519 密钥、keyid、验签
    root_verify.py        # root 结构校验与整链验证
    store.py              # SQLite 存储 + flock 并发控制 + 引导
    settings.py           # 环境变量配置
  bootstrap/
    trusted-root.v1.json  # 首次启动引导 root
  static/
    index.html            # 诊断台（含 TUF 入口）
    roots.html            # TUF 根信任轮换页
    demo/                 # 轮换示例 root 与说明
scripts/
  generate_demo_roots.py  # 固定种子生成引导/示例 root
tests/                    # pytest 测试
Dockerfile, docker-compose.yml, requirements.txt, run.sh
```

## 六、环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TUF_DATA_DIR` | `/data` | SQLite 与锁文件目录（不可写时回退 `./var`） |
| `TUF_DB_PATH` | `${TUF_DATA_DIR}/tuf.db` | SQLite 文件完整路径 |
| `TUF_BOOTSTRAP_ROOT` | `app/bootstrap/trusted-root.v1.json` | 首次启动引导 root |
| `TUF_MAX_UPLOAD_BYTES` | `1048576` | 单份 root 上传大小上限 |
