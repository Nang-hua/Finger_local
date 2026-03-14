# Finger_local

**Finger_local** 是一个 **IDA Pro 本地函数特征识别插件**。

它允许你建立一个 **本地函数特征库**，并在分析新程序时自动根据多维特征对函数进行识别和命名。

插件完全 **离线运行**，不依赖远程服务器。

---

# 功能特点

- 本地函数特征库
    
- 自动函数命名
    
- 多维度特征匹配
    
- 支持评分匹配机制
    
- 支持字符串特征
    
- 支持代码特征
    
- 支持立即数特征
    
- 支持CFG结构特征
    
- 不覆盖用户已命名函数
    
- 支持候选匹配提示
    

---

# 支持的特征

插件会从函数中提取以下特征：

### 结构特征

|特征|说明|
|---|---|
|func_size|函数大小|
|bb_count|basic block 数量|
|edge_count|CFG边数量|
|call_count|调用数量|

---

### 指令特征

|特征|说明|
|---|---|
|mnemonic_norm_hash|指令归一化 hash|
|mnemonic_bag|指令统计|

---

### 代码特征

|特征|说明|
|---|---|
|raw_bytes_hash|原始代码 hash|
|masked_bytes_hash|掩码代码 hash|
|window_hashes|代码滑动窗口 hash|

---

### 常量特征

|特征|说明|
|---|---|
|imm_values|立即数集合|
|anchor_immediates|关键立即数|

---

### 字符串特征

|特征|说明|
|---|---|
|string_refs|引用字符串|
|string_tokens|字符串词元|
|anchor_strings|关键字符串|

---

# 匹配模式

插件支持两种匹配模式：

### strict

严格匹配

当以下特征完全一致时直接命名：

- strict_hash
    
- raw_bytes_hash
    
- masked_bytes_hash
    

---

### scored

评分匹配

通过多维特征计算相似度：

示例评分：

```
masked_bytes_hash   40
mnemonic_norm_hash  25
func_size            8
bb_count             8
call_count           6
imm_values          15
string_refs         20
anchor_strings      25
anchor_immediates   20
window_hashes       15
```

---

# 评分阈值

```
auto_rename : 80
candidate   : 55
```

|分数|行为|
|---|---|
|>= auto_rename|自动命名|
|>= candidate|提示候选|
|< candidate|忽略|

---

# 数据库结构

本地数据库文件：

```
finger_local_db_v2.json
```

结构示例：

```json
{
  "version": 2,
  "functions": [
    {
      "name": "__libc_start_main",
      "arch": "metapc-64-le",
      "source": "manual",
      "desc": "",
      "match_policy": "scored",
      "signature": {
        "strict_hash": "",
        "masked_bytes_hash": "",
        "mnemonic_norm_hash": "",
        "func_size": 312,
        "bb_count": 18,
        "call_count": 5,
        "imm_values": [0,1,8,16,4096],
        "string_refs": ["glibc"],
        "anchor_strings": ["glibc"]
      }
    }
  ]
}
```

---

# 安装方法

复制插件文件：

```
Finger_local_scored.py
finger_local_db_v2.json
```

到 IDA 插件目录：

```
IDA/plugins/
```

例如：

```
D:\IDA93\plugins\
```

重新启动 IDA。

---

# 使用方法

在反汇编窗口点击：

```
Finger_local
```

可用操作：

|菜单|功能|
|---|---|
|Recognize function (local)|识别当前函数|
|Recognize selected functions (local)|识别选中函数|
|Recognize all functions (local)|识别全部函数|
|Add function to local DB|添加函数特征|

---

# 添加函数特征

步骤：

1. 手动识别一个函数
    
2. 修改函数名称
    
3. 点击Finger_local
    

```
Finger_local → Add function to local DB
```

插件会自动：

- 提取函数特征
    
- 写入本地数据库
    

---

# 自动识别

对新样本：

```
Finger_local → Recognize all functions (local)
```

插件会：

1. 提取函数特征
    
2. 与本地库匹配
    
3. 自动重命名函数
    

---

# 安全机制

插件默认：

**不会覆盖已经命名的函数**

只会重命名：

```
sub_xxxxxx
```

这种默认名称函数。

---

# 示例输出

```
[Finger_local] matched: base64_decode score=92
[Finger_local] candidate: aes_decrypt score=68
```

---

# 推荐使用方式

建议逐步积累你的函数库：

例如：

- AES
    
- RC4
    
- XXTEA
    
- CRC32
    
- base64
    
- JSON parser
    
- 自定义加密算法
    
- CTF常见函数
    

随着库增长，识别能力会越来越强。

---

# 与 FLIRT / Lumina 的区别

|工具|说明|
|---|---|
|FLIRT|编译库签名|
|Lumina|IDA云端函数数据库|
|Finger_local|本地自定义函数识别|

Finger_local 更适合：

- CTF
    
- Malware
    
- 固件分析
    
- 私有算法库
    
- 私有函数集合   

---

# 适用版本

推荐：

```
IDA Pro 9.x
```

理论支持：

```
IDA 7.7+
```

---

# License

仅供研究与学习使用。
