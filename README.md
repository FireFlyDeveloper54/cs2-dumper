# cs2-dumper

Counter-Strike 2 外部 offset / schema / SDK dumper。单 exe、默认全量输出。

本仓库是若干公开 GitHub 项目的融合：分析管线来自 [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper)，消费端 include-tree SDK 来自 [scros22/cs2-universal-offsets](https://github.com/scros22/cs2-universal-offsets)，离线 LoadLibrary、注入注册 schema、syscall 读内存等来自下面列出的其它 dumper。**借鉴的东西都可以在 GitHub 找到**，完整出处见 [Credits](#credits)。

默认走 [memflow](https://github.com/memflow/memflow) 外部读内存。它只 dump，不包含作弊功能。

## Build

需要 Rust 1.85+（edition 2024）。仓库根目录：

```text
cargo build --release
```

产物只有一个 `target/release/cs2-dumper.exe`。`-c shade` 用的 payload 在编译时嵌进这个 exe，不需要再带 DLL。

## Usage

```text
cs2-dumper.exe
```

不传参数就会跑完全部阶段，写出 `cs` / `hpp` / `json` / `rs` / `zig` 以及 C++ include-tree。

1. 本机有 `cs2.exe`：attach 后 dump 活进程。
2. 没有游戏进程：从注册表 / `libraryfolders.vdf` / 本地盘自动找 `steamapps/common/Counter-Strike*`，把 schema DLL `LoadLibrary` 进 **dumper 自己的进程** 再 dump（不是注入 `cs2.exe`）。

可选参数：

| 参数 | 说明 |
| --- | --- |
| `-o, --output <DIR>` | 输出目录，默认 `output` |
| `-v` / `-vv` | 更详细的日志 |
| `-c, --connector <name>` | 内存后端，见下表 |
| `--guess-structs` | 额外写出 `structs.hpp`：按字段间距猜测未知类型大小。偏移会显式 pad；`sizeof` 仍可能错。默认关闭 |
| `-h` / `-V` | 帮助 / 版本 |

### Backends (`-c`)

| 名字 | 何时用 |
| --- | --- |
| （默认 / `native`） | memflow-native attach。游戏没开就自动走 LoadLibrary |
| `syscall` | 活 `cs2.exe`，本机 Hell's Gate 风格 `NtReadVirtualMemory` stub（Windows） |
| `shade` | 把内嵌 payload 注入活 `cs2.exe`，对已加载模块调用 `InstallSchemaBindings`，再 dump（Windows） |
| `pcileech` / `kvm` / `winio` | memflow 插件。例如 `cs2-dumper.exe -c pcileech -a :device=FPGA` |

`syscall` 和 `shade` 都要求游戏正在跑。DMA 连接器通常需要管理员 / root。

`manifest.json` 的 `backend` 字段会记下这次跑的是 `native` / `syscall` / `shade` / `loadlib`。

## Output

每次运行同时写两套东西：

- **扁平多语言文件**（和 [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper) 兼容）：`offsets.*`、`buttons.*`、`interfaces.*`、各 `<module>_dll.*`
- **C++ include-tree**（[scros22/cs2-universal-offsets](https://github.com/scros22/cs2-universal-offsets) 那一套）：`cs2.hpp` 单头 amalgamation + `macros.hpp` + `schemas/` + `impl/entity_system.hpp`

```text
<output>/
├── manifest.json
├── info.json
├── cs2.hpp                          # C++ 单头
├── macros.hpp                       # SCHEMA_FIELD + engine types + auto forwards
├── offsets.{cs,hpp,json,rs,zig}     # canonical dwXxx
├── offsets_merged.{hpp,json}        # canonical + pattern + interface RVA
├── buttons.*  interfaces.*
├── <module>_dll.{cs,hpp,json,rs,zig}
├── patterns.{json,hpp,md,...}
├── vtables.{json,hpp,cs}            # hpp 还会拷到 offsets/vtables.hpp
├── schema_index.json
├── schema_index.diff.json
├── sdk/
│   ├── sdk.hpp
│   ├── sdk_types.hpp
│   ├── sdk_enums.hpp
│   ├── sdk_classes.hpp
│   ├── modules.hpp
│   ├── modules/<module>.hpp
│   └── classes/<module>/<Class>.hpp
├── schemas/
│   ├── schemas.json
│   └── <module>_dll.hpp             # 带命名空间的 typed class
├── offsets/offsets.hpp
├── offsets/vtables.hpp
├── patterns/patterns.hpp
├── interfaces/interfaces.hpp        # 可调用 vtable 结构 + ASLR-safe getter
├── impl/entity_system.hpp
├── engine/
│   ├── engine_structs.json
│   ├── ccsgoinput.h
│   ├── cusercmd.h
│   └── cviewsetup.h
├── netvars/
├── convars/
├── protobufs/
├── entities/
├── weapons/
├── gameevents/
└── verified_features.json
```

活进程还能写出 convars、entities、weapons、game events、netvars、protobufs。LoadLibrary 模式没有这些运行时对象，schema / pattern / interface 仍然有。

`schema_index.json` 里 enum 的 `size` 是 schema 存储宽度（字节），成员个数是 `members`。

| 你要干什么 | 用哪个文件 |
| --- | --- |
| C++ 一个 include 全要 | `cs2.hpp` |
| C++ typed schema class | `macros.hpp` + `schemas/client_dll.hpp` |
| C++ 走 entity list | `impl/entity_system.hpp` |
| 任意语言只要常量 | `offsets.hpp` / `<module>_dll.json` |
| 更新后对 diff | `manifest.json` + `*.diff.json` + `patterns.repair.patch.json` |
| 按 vtable index hook | `vtables.hpp` / `vtables.json` |
| schema 标志（vtable / abstract / scope） | `schema_index.json` 的 `flags`，以及 `schemas/*.hpp` 注释 |
| dump 时没加载的模块 | `manifest.json` `missing_schema_modules` |

## 怎么用生成的 SDK

C++ 把 dump 目录加进 include path，然后：

```text
my-project/
├── src/
└── vendor/cs2-dumper/          # 拷一份 <output>/
    ├── cs2.hpp
    ├── macros.hpp
    ├── schemas/
    ├── impl/
    └── ...
```

```cpp
#include <cs2.hpp>

static_assert(CS2_BUILD != 0, "dump must record a live build number");

int health(void* pawn_ptr) {
    auto* pawn = reinterpret_cast<client::C_CSPlayerPawn*>(pawn_ptr);
    return pawn->m_iHealth();
}
```

`cs2.hpp` 会拉上 `macros.hpp`、各模块 schema（编辑器模块会跳过）、merged offsets、typed interfaces、buttons、protobufs、patterns、entity helper、engine 结构。缺的可选报告用 `__has_include` 挡住，照样能编。扁平的 `sdk/sdk.hpp` 还在，给要全局命名空间那套的人用。

Entity helper 在 `impl/entity_system.hpp`，走 `offsets::` 常量，不写死数字：

```cpp
auto* local = CGameEntitySystem::GetLocalPlayer();
auto* identity = CGameEntitySystem::GetIdentityByIndex(1);
```

Interface 单例是 ASLR-safe 的，自己把模块基址传进去：

```cpp
auto* input = ifc::inputsystem::get_InputSystemVersion001(module_base);
input->SetRelativeMouseMode(false);
void* slot = ifc::detail::vtable_slot(input, 76);
```

C# / Rust / Zig / JSON 用扁平多语言文件（`offsets.json`、`client_dll.cs`、`patterns.rs` …）。include-tree 只给 C++。

游戏更新后：对着新 build 再跑一遍 dumper，看 `manifest.json`（`build_number`、`pattern_summary`），再看 `patterns.diff.json` / `schema_index.diff.json` / `interfaces.diff.json`。特征漂了会写出 `patterns.repair.json` 和可直接喂回去的 `patterns.repair.patch.json`。然后用新的 `cs2.hpp` 重编消费端。

## Schema

Source 2 自带运行时元数据，不用 PDB 也能还原 class / enum / netvar / metadata。

引擎启动时建 `CSchemaSystem` 单例。每个用 schema 的模块注册一个 `CSchemaSystemTypeScope`（一 DLL 一 scope），scope 里是 `CUtlTSHash`，装着该模块的 `CSchemaClassBinding` / `CSchemaEnumBinding`。

每个 class 有：名字、可选父类、字段（名字 / 类型字符串 / 实例内偏移）、编译期 metadata。最常用的两条是 `MNetworkVarNames(name, type)` 和 `MNetworkChangeCallback(name)`。enum 同样是名字 + 对齐 + `(name, value)` 列表。

Walker 在 `src/source2/`：

1. pelite 扫 PE，用特征定位 schema 系统（特征在 `src/analysis/offsets.rs`）。
2. memflow 顺着 `CUtlTSHash` 枚举每个 scope 的 class / enum。
3. `src/analysis/schemas.rs` 拍扁成 emitter 用的 `Class` / `Enum`。

两套写出：

```cpp
// 扁平常量（任意语言）
namespace cs2_dumper::schemas::client_dll::C_CSPlayerPawn {
    constexpr std::ptrdiff_t m_iHealth = 0x344;
}

// include-tree typed class
namespace cs2::sdk::client_dll {
    class C_CSPlayerPawn : public C_BasePlayerPawn {
    public:
        SCHEMA_FIELD(std::int32_t, m_iHealth, 0x344)
    };
}
```

`SCHEMA_FIELD` 在 `macros.hpp`，展开成 `this + offset` 的 typed 访问器。带 `MNetworkVarNames` 的字段还会单独写到 `netvars/`。

相关代码：`src/source2/`、`src/analysis/schemas.rs`、`src/output/schemas.rs`、`src/output/sdk_classes.rs`、`src/output/netvars.rs`。

## Patterns

特征是 IDA 风格字节串，空格分隔，`?` / `??` 是通配，也支持半字节通配（`4?`、`?A`）。扫描器基于 [pelite](https://github.com/CasualX/pelite)，只扫指定模块的指定 PE 节（代码走 `.text`，字符串走 `.rdata`）。

匹配地址是 pattern **第一个字节** 的 RVA。真正要的值往往在后面的 `lea` / `call` / `mov` 里，所以每条特征带一个 resolver：

| resolve | 干什么 |
| --- | --- |
| `raw` / `None` | 匹配地址就是结果（函数头，直接 hook） |
| `rel32` | `E8`/`E9` 的 signed disp32。`rel_off` 是 disp 相对 pattern 起点的字节下标，通常是 `1` |
| `riprel` | `48 8D 0D disp32` 这类 RIP-relative。`48 8D 0D` 时 `rel_off` 是 `3` |
| `stringref` | 先在 `.rdata` 找字符串，再合成 `lea rXX, [rip+str]` 去 `.text` 里做 riprel |

`rel32` / `riprel` 算法一样：

```text
disp = i32::from_le_bytes(text[match_rva + rel_off ..][..4])
RVA  = match_rva + rel_off + 4 + disp
```

内置库在 `src/patterns/database.rs`。每条扫完记 match 次数；一条挂了不会把整次 dump 带崩。上次的 `patterns.json` 会先在缓存的 `match_rva` 上复验，没漂就跳过全模块扫描。

写出 `patterns.{json,hpp,md,cs,rs,zig}`。漂了的特征会尝试放宽通配，结果进 `patterns.repair.json`；其中唯一命中的子集写成 `patterns.repair.patch.json`。

### 加一条特征

1. 在 IDA / Ghidra / Binary Ninja 里找到函数。
2. 抽 12–20 个跨更新还在的字节：函数序言、唯一常量加载、有名字的 import。别用大段 `mov reg, reg`，也别把每补丁都变的立即数写死。
3. 会变的位移 / 寄存器编码改成 `??` 或半字节通配。
4. 选 resolver：序言用 `None`；`E8`/`E9` 用 `Rel32 { rel_off: 1 }`；`48 8D 0D` 用 `RipRel { rel_off: 3 }`。`rel_off` 差 1 会得到看起来像那么回事但错的 RVA。
5. 追加到 `src/patterns/database.rs` 的 `CS2_PATTERNS`：

```rust
Pattern {
    name: "MyNewThing",
    module: "client.dll",
    needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ?",
    resolve: NONE,
    extra_off: 0,
    prototype: "",
},
```

6. `cargo build --release`，再跑一次 dumper。看 `patterns.json`：`found`、`matches`（必须是 1）、`rva`。拿 RVA 回反汇编器对一下。

## Vtables

对每个解析到的 interface，跟实例指针的第一个 qword 拿到 `vftable`，再当连续函数指针数组往下走，直到槽位不落在任何已加载模块镜像里。写出 `vtables.{json,hpp,cs}`，hpp 再拷到 include-tree 的 `offsets/vtables.hpp`。

没有 PDB。多数槽是 `method_<N>`，直接用下标。额外会拿槽的 RVA 去对 pattern 库，对上了就用特征名（例如 `update_global_vars`）。MSVC `/GR` 下还能顺着 vtable `[-1]` 的 `RTTICompleteObjectLocator` 解出 C++ 类名。

vtable 布局比函数体字节稳得多：槽位下标只有 Valve 给虚函数增删改序才会变。

```cpp
#include <cs2.hpp>

using CreateMove_t = bool(__thiscall*)(void* self, int slot, float ft, bool active);

void hook_create_move(void* iface) {
    auto** vt = *reinterpret_cast<void***>(iface);
    auto* fn = vt[cs2::vtables::client_dll::Source2Client002::method_25];
    install_hook(fn, &your_create_move_hook);
}
```

`vtables.json` 的 `vtable_module` 是 vftable 字节所在的 DLL（实现有时在兄弟模块里）。Walker 在 `src/analysis/vtables.rs`，写出在 `src/output/vtables.rs`。

## Tests

```text
cargo test --workspace
```

需要活 `cs2.exe` 的检查：

```text
cargo test -- --ignored --nocapture
```

## Credits

下面这些都是公开 GitHub 仓库。本项目只取各自强项，拼进一条管线。

### Dumpers this tree is based on

| 仓库 | 拿了什么 |
| --- | --- |
| [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper) | 主体：memflow attach、schema / interface / button / offset 扫描、多语言输出、pattern 修复与动态恢复 |
| [scros22/cs2-universal-offsets](https://github.com/scros22/cs2-universal-offsets) | 带命名空间的 C++ include-tree、`SCHEMA_FIELD`、自动前向声明、typed entity helper、engine 结构布局 |
| [bt629414/cs2-best-dumper](https://github.com/bt629414/cs2-best-dumper) | 额外 `dwCreateMove` / `dwParticleManager` / `dwClientMode` / `dwPVSManager` / `dwVPhys2World`、磁盘 PE 回退、可选 syscall RPM（`-c syscall`）、`--guess-structs` |
| [arisuwine/shade-dumper](https://github.com/arisuwine/shade-dumper) | 完整 `SCHEMA_CF1_*` / `SCHEMA_EF_*` 标签、vtable slot dump、可选注入后调用 `InstallSchemaBindings`（`-c shade`） |
| [xsip/cs2-schema-dumper-no-process](https://github.com/xsip/cs2-schema-dumper-no-process) | 游戏没开时：找 Steam 安装、对本进程 `LoadLibrary` schema DLL 再 dump |

### Libraries and related Source 2 tools

| 仓库 | 角色 |
| --- | --- |
| [memflow/memflow](https://github.com/memflow/memflow) | 跨平台内存读写框架（默认后端） |
| [memflow/memflow-native](https://github.com/memflow/memflow-native) | Windows 本机 attach |
| [CasualX/pelite](https://github.com/CasualX/pelite) | PE 解析与特征扫描 |
| [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate) | `-c syscall`：从 ntdll stub 抽 SSN 再调 `NtReadVirtualMemory` |
| [neverlosecc/source2gen](https://github.com/neverlosecc/source2gen) | Source 2 schema → C++ SDK 的常见写法（`SCHEMA_FIELD` 这一路） |
| [GAMMACASE/Source2SchemaDumper](https://github.com/GAMMACASE/Source2SchemaDumper) | 服务端 schema dump（CS2 / Dota 2 / Deadlock） |
| [sneakyevil/CS2-SchemaDumper](https://github.com/sneakyevil/CS2-SchemaDumper) | 早期外部 schema walker |
| [ValveResourceFormat/DumpSource2](https://github.com/ValveResourceFormat/DumpSource2) | 离线 schema / convar dump（GameTracking 在用） |
| [a2x/cs2-analyzer](https://github.com/a2x/cs2-analyzer) | a2x 的离线分析器（WIP） |

## License

MIT（[LICENSE](./LICENSE)）。上游项目保留各自许可证；本仓库的分析与输出代码按 MIT 发布。
