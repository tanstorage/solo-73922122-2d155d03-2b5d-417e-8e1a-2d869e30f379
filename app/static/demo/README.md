# TUF root 轮换演示数据（TUF 1.0.37，仅 Ed25519）

由 `scripts/generate_demo_roots.py` 以固定种子生成，可重复构建。
引导受信 root 为 `app/bootstrap/trusted-root.v1.json`（version=1，阈值 2，密钥 K1/K2/K3）。

## 合法链（3 份，v2 → v3 → v4）

| 文件 | 版本 | root 密钥 | 阈值 | expires | 签名密钥 |
| --- | --- | --- | --- | --- | --- |
| root.v2.json | 2 | K1/K2/K3 | 2 | 2026-10-01T00:00:00Z（中间根，允许过期） | K1/K2 |
| root.v3.json | 3 | K3/K4 | 2 | 2026-10-01T00:00:00Z（中间根，允许过期） | K1/K2（上一版阈值）+ K3/K4（自身阈值） |
| root.v4.json | 4 | K3/K4/K5 | 2 | 2032-12-31T00:00:00Z（晚于更新开始时间） | K3/K4 |

要点：v3 完成密钥轮换（K1/K2 退出，K4 加入，K3 桥接），每份都同时满足
上一版 root 与自身 root 的角色阈值；v1/v2/v3 已过期但作为中间根被允许。

## 失败链

* `root.bad-threshold.v4.json`：v4 把 root 阈值提高到 3，但 root 角色只登记
  K3/K4 两个 keyid（去重后最多 2 个有效签名），且 K5 未登记进 root 角色、其签名被忽略
  → 自身阈值不足，整链拒绝。
* `root.bad-expired.v4.json`：v4 签名全部有效，但 expires=2026-10-01T00:00:00Z，
  作为最终根早于本次更新开始时间到期 → 整链拒绝。

失败时服务保留原受信 root，并在响应与审计记录中给出失败版本和原因。

## keyid（sha256(canonical JSON(key))）

| 名称 | keyid |
| --- | --- |
| K1 | `7ab6b86cb2c9684b0ddc10896153aa2595decf4d4327a5ff1a8ab7422c828b12` |
| K2 | `c3f860ca5da4454d33496ca33bb48f0cdcd5b731be7316b67ca191db0185aa26` |
| K3 | `8bf5a507dc237a32c90c0a23b34bab6b386826145a5b726da75c91d466e4bf33` |
| K4 | `3336b222894653a1c328c2636b5ada9d8c2f53be3b927369d64e7087014bf619` |
| K5 | `e9d933784bfeb1d51791fdd145c115646e16ccff141fedbfaf2dea96bb2abf0e` |
